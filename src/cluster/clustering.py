"""Etapa 7: clustering de respuestas HTTP contra la linea base de referencia.

Esta etapa no genera trafico: trabaja sobre las respuestas que ZAP provoco en
la etapa 6 (results/respuestas_zap.csv). Por cada par (ruta, CWE):

  1. Se toman los rasgos de la linea base de referencia de esa ruta (la
     respuesta a la entrada valida del crawler) y los de todas las respuestas
     que ZAP provoco con sus propias pruebas. No es una pagina de rechazo: ver
     el aviso de terminologia en src/verify/verify_with_zap.py.
  2. Los tres rasgos son el codigo de estado, la longitud de la respuesta y la
     similitud de contenido con la linea base. Se estandarizan y se agrupan con
     DBSCAN.
  3. Si alguna respuesta provocada por ZAP cae fuera del grupo de la linea
     base, el comportamiento de la aplicacion cambio ante el ataque y el
     hallazgo queda "confirmado". Si todas caen en el mismo grupo, la respuesta
     es indistinguible de la linea base y queda "descartado".

Un hallazgo sin ruta HTTP, o de un CWE que ZAP no puede probar, queda
"no_verificable" y se conserva.

El veredicto final de cada hallazgo combina las dos senales disponibles: la
alerta de ZAP de la etapa 6 y la separacion de comportamiento de esta etapa.
Basta con que una de las dos confirme.

Los hallazgos propios de ZAP **no pasan por el agrupamiento**: quedan como
"observado_dast" y C4 los conserva sin filtrar. El motivo es que ya son una
observacion dinamica, de modo que confirmarlos con otra observacion dinamica
seria circular. La consecuencia, que conviene declarar, es que el filtro de C4
actua solo sobre los hallazgos SAST: los 10 falsos positivos de ZAP pasan
siempre, y la reduccion medida es reduccion de falsos positivos del SAST.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from typing import Any

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from ..common import provenance
from ..common.config import repo_root
from ..verify.verify_with_zap import (
    SALIDA as ENTRADA,
    SALIDA_RESPUESTAS,
    SCHEMA_VERIFICADO,
)

SALIDA = "results/hallazgos.csv"
SCHEMA_FINAL = SCHEMA_VERIFICADO + [
    # Agrupamiento contra la respuesta normal de la ruta (implementacion inicial)
    "estado_clustering",
    # Veredicto de la regla trivial de invariancia, que no usa DBSCAN. Se
    # registra para poder medir que aporta el agrupamiento (ver invariancia()).
    "estado_invariancia",
    # Agrupamiento contra las clases de rechazo Rr y Rii, fiel a Akrout (2014).
    # Se calculan los tres sobre el mismo trafico para poder compararlos sin
    # que la variabilidad del escaneo entre ejecuciones contamine el resultado.
    "estado_clustering_akrout",
    # Regla trivial sin DBSCAN, misma referencia que estado_clustering_akrout.
    # Comprueba si el agrupamiento aporta algo tambien cuando se le da la
    # referencia de rechazo "correcta" segun Akrout, no solo con la linea base
    # normal (ver invariancia_akrout()).
    "estado_invariancia_akrout",
    "estado_final",
    "n_respuestas_zap",
]

# Estados que C4 conserva: solo se descarta lo que ZAP pudo probar y no confirmo.
ESTADOS_CONSERVADOS = ("confirmado", "no_verificable", "observado_dast")


def carga_respuestas(cfg: dict[str, Any]) -> dict[tuple[str, int], dict[str, list]]:
    """Agrupa las respuestas capturadas por par (ruta, CWE)."""
    ruta = repo_root() / SALIDA_RESPUESTAS
    if not ruta.exists():
        raise RuntimeError(f"No existe {SALIDA_RESPUESTAS}: ejecuta antes la etapa verify.")

    # Tipos posibles: linea_base (respuesta a la entrada valida del rastreo),
    # ref_rr y ref_rii (las dos clases de rechazo de Akrout) y prueba_zap (las
    # respuestas que provoco el escaneo activo dirigido).
    grupos: dict[tuple[str, int], dict[str, list]] = defaultdict(
        lambda: defaultdict(list)
    )
    with open(ruta, "r", encoding="utf-8", newline="") as fh:
        for fila in csv.DictReader(fh):
            try:
                clave = (fila["ruta_http"], int(fila["cwe"]))
                # Los tres primeros rasgos son los del metodo descrito en la
                # memoria; el cuarto (parecido con una respuesta de rechazo de
                # la misma ruta) solo lo usa la variante fiel a Akrout.
                rasgos = [
                    float(fila["status"]),
                    float(fila["longitud"]),
                    float(fila["similitud"]),
                    float(fila.get("similitud_rechazo") or 0.0),
                ]
            except (KeyError, TypeError, ValueError):
                continue
            grupos[clave][fila["tipo"]].append(rasgos)
    return grupos


def agrupa(
    linea_base: list[list[float]], pruebas: list[list[float]], cfg: dict[str, Any]
) -> tuple[str, str]:
    """Decide si alguna respuesta de ZAP se separa de la linea base."""
    if not pruebas:
        return "no_verificable", "ZAP no provoco ninguna respuesta sobre esta ruta"
    if not linea_base:
        return "no_verificable", "sin linea base de referencia para esta ruta"

    cl = cfg["clustering"]
    # Solo los tres rasgos del metodo original de este trabajo
    X = np.asarray([f[:3] for f in linea_base + pruebas], dtype=float)
    if np.allclose(X.std(axis=0), 0):
        # Todas las respuestas son identicas: no hay separacion posible.
        return "descartado", "todas las respuestas son identicas a la linea base"

    Xs = StandardScaler().fit_transform(X)
    etiquetas = DBSCAN(eps=cl["eps"], min_samples=cl["min_samples"]).fit_predict(Xs)
    grupos_base = set(etiquetas[: len(linea_base)])
    etiquetas_pruebas = etiquetas[len(linea_base):]

    separadas = int(sum(1 for g in etiquetas_pruebas if g not in grupos_base))
    if separadas:
        return (
            "confirmado",
            f"{separadas}/{len(pruebas)} respuestas de ZAP se separan de la linea base",
        )
    return "descartado", "todas las respuestas de ZAP coinciden con la linea base"


def agrupa_akrout(
    rechazo: list[list[float]], pruebas: list[list[float]], cfg: dict[str, Any]
) -> tuple[str, str]:
    """Regla de Akrout et al. (2014): comparar contra las clases de rechazo.

    `rechazo` son las respuestas a las peticiones Rr (valores aleatorios) y Rii
    (valores malformados), es decir Sr union Sii. Se agrupan junto con las
    respuestas al ataque y, citando el articulo, «las peticiones Rvi cuyas
    respuestas no son similares a ninguna de las respuestas de Sii y Sr se
    consideran inyecciones validas».

    La diferencia con agrupa() es la referencia: alli es el comportamiento
    normal de la ruta, aqui es su comportamiento al rechazar. Con dos clases y
    varias muestras de cada una, DBSCAN tiene estructura de densidad real que
    agrupar, que es la condicion que el metodo original supone.
    """
    if not pruebas:
        return "no_verificable", "ZAP no provoco ninguna respuesta sobre esta ruta"
    if not rechazo:
        return "no_verificable", "sin clases de rechazo (Rr/Rii) para esta ruta"

    cl = cfg["clustering"]
    X = np.asarray(rechazo + pruebas, dtype=float)
    if np.allclose(X.std(axis=0), 0):
        return "descartado", "el ataque responde igual que las peticiones rechazadas"

    Xs = StandardScaler().fit_transform(X)
    etiquetas = DBSCAN(eps=cl["eps"], min_samples=cl["min_samples"]).fit_predict(Xs)
    grupos_rechazo = set(etiquetas[: len(rechazo)])
    etiquetas_pruebas = etiquetas[len(rechazo):]

    separadas = int(sum(1 for g in etiquetas_pruebas if g not in grupos_rechazo))
    if separadas:
        return (
            "confirmado",
            f"{separadas}/{len(pruebas)} respuestas no se parecen a ninguna de Sr ni Sii",
        )
    return "descartado", "todas las respuestas al ataque caen en las clases de rechazo"


def invariancia(
    linea_base: list[list[float]], pruebas: list[list[float]]
) -> tuple[str, str]:
    """Regla de referencia sin DBSCAN: ¿alguna respuesta difiere de la linea base?

    Existe para poder medir que aporta el agrupamiento en vez de deducirlo. Es la
    alternativa trivial: se compara cada respuesta provocada por ZAP con la linea
    base en los tres mismos rasgos (codigo de estado, longitud y similitud) y
    basta una diferencia exacta para confirmar. Si DBSCAN no descarta ningun par
    que esta regla confirme, y viceversa, el agrupamiento no esta aportando nada
    sobre una simple prueba de invariancia de la respuesta.
    """
    if not pruebas:
        return "no_verificable", "ZAP no provoco ninguna respuesta sobre esta ruta"
    if not linea_base:
        return "no_verificable", "sin linea base de referencia para esta ruta"

    base = linea_base[0]
    distintas = sum(1 for p in pruebas if p != base)
    if distintas:
        return "confirmado", f"{distintas}/{len(pruebas)} respuestas difieren de la linea base"
    return "descartado", "todas las respuestas son identicas a la linea base"


def invariancia_akrout(
    rechazo: list[list[float]], pruebas: list[list[float]]
) -> tuple[str, str]:
    """Regla trivial sin DBSCAN, pero contra las clases de rechazo de Akrout.

    Misma logica que invariancia(), cambiando la referencia: en vez de una
    sola linea base, aqui hay que no coincidir con NINGUNA de las respuestas de
    Sr union Sii. Existe para la misma comprobacion que invariancia() pero
    aplicada al metodo de Akrout: si DBSCAN no aporta nada sobre esta regla,
    tampoco aporta nada cuando se le da la referencia "correcta" segun el
    articulo original, y el problema no era la referencia sino el algoritmo.
    """
    if not pruebas:
        return "no_verificable", "ZAP no provoco ninguna respuesta sobre esta ruta"
    if not rechazo:
        return "no_verificable", "sin clases de rechazo (Rr/Rii) para esta ruta"

    rechazo_set = {tuple(r) for r in rechazo}
    distintas = sum(1 for p in pruebas if tuple(p) not in rechazo_set)
    if distintas:
        return "confirmado", f"{distintas}/{len(pruebas)} respuestas no coinciden con ninguna de Sr/Sii"
    return "descartado", "todas las respuestas coinciden con alguna de Sr/Sii"


def veredicto(confirmacion: str, clustering: str) -> str:
    """Combina la alerta de ZAP (etapa 6) y la separacion de comportamiento (7)."""
    if confirmacion == "observado_dast":
        return "observado_dast"
    if confirmacion == "confirmado" or clustering == "confirmado":
        return "confirmado"
    if confirmacion == "no_verificable" and clustering == "no_verificable":
        return "no_verificable"
    if clustering == "descartado" or confirmacion == "no_confirmado":
        return "descartado"
    return "no_verificable"


def run_stage(cfg: dict[str, Any]) -> None:
    origen = repo_root() / ENTRADA
    if not origen.exists():
        raise RuntimeError(f"No existe {ENTRADA}: ejecuta antes la etapa verify.")
    with open(origen, "r", encoding="utf-8", newline="") as fh:
        filas = list(csv.DictReader(fh))

    with provenance.stage("7-cluster") as ctx:
        grupos = carga_respuestas(cfg)
        print(f"Pares (ruta, CWE) con respuestas capturadas: {len(grupos)}")

        decisiones: dict[tuple[str, int], tuple[str, str, int]] = {}
        invariancias: dict[tuple[str, int], str] = {}
        akrout: dict[tuple[str, int], tuple[str, str]] = {}
        invariancias_akrout: dict[tuple[str, int], str] = {}
        for clave, datos in grupos.items():
            estado, evidencia = agrupa(datos["linea_base"], datos["prueba_zap"], cfg)
            decisiones[clave] = (estado, evidencia, len(datos["prueba_zap"]))
            invariancias[clave] = invariancia(datos["linea_base"], datos["prueba_zap"])[0]
            rechazo = datos["ref_rr"] + datos["ref_rii"]
            akrout[clave] = agrupa_akrout(rechazo, datos["prueba_zap"], cfg)
            invariancias_akrout[clave] = invariancia_akrout(rechazo, datos["prueba_zap"])[0]

        # Comparacion DBSCAN vs. regla trivial, sobre los pares realmente
        # agrupados. Es la evidencia que exige la critica A1 del tribunal.
        comparables = [c for c in grupos if decisiones[c][0] != "no_verificable"]
        discrepancias = [c for c in comparables if decisiones[c][0] != invariancias[c]]
        solo_dbscan_descarta = [
            c for c in comparables
            if decisiones[c][0] == "descartado" and invariancias[c] == "confirmado"
        ]

        resumen_cluster: dict[str, int] = {}
        resumen_final: dict[str, int] = {}
        for fila in filas:
            try:
                cwe = int(fila["cwe"])
            except (TypeError, ValueError):
                cwe = -1
            clave = (fila.get("ruta_http", ""), cwe)

            if fila["herramienta"] == "zap":
                estado, evidencia, n = "no_verificable", "", 0
            elif clave in decisiones:
                estado, evidencia, n = decisiones[clave]
            else:
                estado, evidencia, n = "no_verificable", "sin respuestas de ZAP para este par", 0

            fila["estado_clustering"] = estado
            es_zap = fila["herramienta"] == "zap"
            fila["estado_invariancia"] = (
                "no_verificable" if es_zap else invariancias.get(clave, "no_verificable")
            )
            fila["estado_clustering_akrout"] = (
                "no_verificable" if es_zap else akrout.get(clave, ("no_verificable", ""))[0]
            )
            fila["estado_invariancia_akrout"] = (
                "no_verificable" if es_zap else invariancias_akrout.get(clave, "no_verificable")
            )
            fila["n_respuestas_zap"] = n
            if evidencia:
                previa = fila.get("evidencia_zap") or ""
                fila["evidencia_zap"] = f"{previa} | 7: {evidencia}".strip(" |")
            fila["estado_final"] = veredicto(fila.get("estado_confirmacion", ""), estado)

            resumen_cluster[estado] = resumen_cluster.get(estado, 0) + 1
            resumen_final[fila["estado_final"]] = resumen_final.get(fila["estado_final"], 0) + 1

        destino = repo_root() / SALIDA
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=SCHEMA_FINAL)
            escritor.writeheader()
            for fila in filas:
                escritor.writerow({c: fila.get(c, "") for c in SCHEMA_FINAL})

        ctx["detail"] = (
            f"clustering={resumen_cluster}; final={resumen_final}; "
            f"pares agrupados={len(comparables)}; "
            f"discrepancias DBSCAN vs invariancia={len(discrepancias)}"
        )

    print(f"Clustering -> {SALIDA}")
    print("  por clustering de respuestas:")
    for estado, n in sorted(resumen_cluster.items()):
        print(f"    {estado}: {n}")
    print("  veredicto final (alerta de ZAP + separacion de comportamiento):")
    for estado, n in sorted(resumen_final.items()):
        print(f"    {estado}: {n}")
    comp_akrout = [c for c in grupos if akrout[c][0] != "no_verificable"]
    conf_akrout = sum(1 for c in comp_akrout if akrout[c][0] == "confirmado")
    print("  agrupamiento fiel a Akrout (contra las clases de rechazo Rr/Rii):")
    print(f"    pares con clases de rechazo disponibles: {len(comp_akrout)}")
    print(f"    confirmados por esa regla:               {conf_akrout}")
    print(f"    descartados por esa regla:               {len(comp_akrout) - conf_akrout}")
    distintos = sum(
        1 for c in grupos
        if akrout[c][0] != "no_verificable" and decisiones[c][0] != "no_verificable"
        and akrout[c][0] != decisiones[c][0]
    )
    print(f"    veredictos distintos frente a la linea base normal: {distintos}")
    comparables_akrout = [c for c in grupos if akrout[c][0] != "no_verificable"]
    discrepancias_akrout = [
        c for c in comparables_akrout if akrout[c][0] != invariancias_akrout[c]
    ]
    print("  que aporta DBSCAN sobre la regla trivial, dandole la MISMA referencia de Akrout:")
    print(f"    pares comparables:                          {len(comparables_akrout)}")
    print(f"    veredictos distintos entre las dos reglas:  {len(discrepancias_akrout)}")
    print(f"  que aporta DBSCAN sobre la regla trivial de invariancia:")
    print(f"    pares agrupados (no 'no_verificable'):          {len(comparables)}")
    print(f"    veredictos distintos entre las dos reglas:      {len(discrepancias)}")
    print(f"    pares que DBSCAN descarta y la regla confirma:  {len(solo_dbscan_descarta)}")
    if solo_dbscan_descarta[:3]:
        print("    ejemplos:")
        for ruta, cwe in solo_dbscan_descarta[:3]:
            print(f"      CWE-{cwe} {ruta}")
