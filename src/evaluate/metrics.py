"""Etapa 8: evaluacion contra expectedresults-1.2.csv.

Metodologia de puntuacion del OWASP Benchmark, replicada aqui:

  - La unidad de evaluacion es el par (caso de prueba, CWE), no el hallazgo.
    Varios hallazgos de la misma herramienta sobre el mismo caso y el mismo CWE
    cuentan como una sola deteccion. Por eso los totales crudos (por ejemplo
    8233 hallazgos de SpotBugs) no son el numero de falsos positivos.
  - La puntuacion se calcula por categoria: para el CWE C, solo se consideran
    los casos de prueba cuya categoria esperada es C. Una deteccion de CWE-79
    sobre un caso de inyeccion SQL no se cuenta ni como acierto ni como fallo,
    igual que hace el scorer oficial del proyecto.
  - TPR = TP/(TP+FN), FPR = FP/(FP+TN) y Benchmark Score = TPR - FPR.

La reduccion de falsos positivos se mide siempre contra C1 (union de los
motores SAST), que es la linea base que el TFT quiere mejorar.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable

from ..common import provenance
from ..common.config import repo_root

SALIDA_METRICAS = "results/metrics.csv"
SALIDA_RESUMEN = "results/resumen_hallazgos.csv"
BASE_REDUCCION_FP = "C1"

COLUMNAS = [
    "configuracion",
    "descripcion",
    "cwe",
    "casos",
    "TP",
    "FP",
    "FN",
    "TN",
    "precision",
    "recall",
    "f1",
    "tpr",
    "fpr",
    "benchmark_score",
    "reduccion_fp_vs_" + BASE_REDUCCION_FP,
]


def carga_verdad(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Lee la verdad de referencia: caso -> {cwe, categoria, vulnerable}."""
    ruta = repo_root() / cfg["benchmark"]["expected_results_csv"]
    verdad: dict[str, dict[str, Any]] = {}
    with open(ruta, "r", encoding="utf-8", newline="") as fh:
        for fila in csv.reader(fh):
            if not fila or fila[0].startswith("#"):
                continue
            caso, categoria, real, cwe = fila[0].strip(), fila[1].strip(), fila[2].strip(), fila[3].strip()
            verdad[caso] = {
                "categoria": categoria,
                "vulnerable": real.lower() == "true",
                "cwe": int(cwe),
            }
    return verdad


def _metricas(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    tpr = recall
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tpr": round(tpr, 4),
        "fpr": round(fpr, 4),
        "benchmark_score": round(tpr - fpr, 4),
    }


def evalua(
    detecciones: set[tuple[str, int]],
    verdad: dict[str, dict[str, Any]],
    cwes: Iterable[int],
) -> dict[str, dict[str, Any]]:
    """Calcula las metricas por CWE y el total, para un conjunto de detecciones.

    `detecciones` son pares (caso, cwe) ya deduplicados.
    """
    resultado: dict[str, dict[str, Any]] = {}
    acumulado = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "casos": 0}

    for cwe in cwes:
        casos = [c for c, d in verdad.items() if d["cwe"] == cwe]
        tp = fp = fn = tn = 0
        for caso in casos:
            detectado = (caso, cwe) in detecciones
            vulnerable = verdad[caso]["vulnerable"]
            if detectado and vulnerable:
                tp += 1
            elif detectado and not vulnerable:
                fp += 1
            elif not detectado and vulnerable:
                fn += 1
            else:
                tn += 1
        fila = {"casos": len(casos), "TP": tp, "FP": fp, "FN": fn, "TN": tn}
        fila.update(_metricas(tp, fp, fn, tn))
        resultado[str(cwe)] = fila
        for k in ("TP", "FP", "FN", "TN", "casos"):
            acumulado[k] += fila[k]

    total = dict(acumulado)
    total.update(_metricas(acumulado["TP"], acumulado["FP"], acumulado["FN"], acumulado["TN"]))
    resultado["TOTAL"] = total
    return resultado


def detecciones_de(filas: Iterable[dict[str, str]], cwes: set[int]) -> set[tuple[str, int]]:
    """Convierte filas de hallazgos en pares (caso, cwe) deduplicados."""
    salida: set[tuple[str, int]] = set()
    for fila in filas:
        caso = fila.get("caso", "")
        cwe = fila.get("cwe", "")
        if not caso or not cwe:
            continue
        try:
            valor = int(cwe)
        except ValueError:
            continue
        if valor in cwes:
            salida.add((caso, valor))
    return salida


def configuraciones(filas: list[dict[str, str]], cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Construye el conjunto de detecciones de cada configuracion del experimento.

    C0 se desglosa en un conjunto por motor; el resto son uniones. C4 usa solo
    los hallazgos que la verificacion cruzada no descarto.
    """
    cwes = set(cfg["evaluation"]["benchmark_cwes"])
    descripciones = cfg["evaluation"]["configurations"]

    por_motor = {
        motor: [f for f in filas if f["herramienta"] == motor]
        for motor in ("semgrep", "spotbugs", "zap")
    }
    sast = por_motor["semgrep"] + por_motor["spotbugs"]
    dast = por_motor["zap"]

    confs: dict[str, dict[str, Any]] = {}
    for motor, subconjunto in por_motor.items():
        if subconjunto:
            confs[f"C0-{motor}"] = {
                "descripcion": f"{descripciones['C0']} [{motor}]",
                "detecciones": detecciones_de(subconjunto, cwes),
            }

    if sast:
        confs["C1"] = {
            "descripcion": descripciones["C1"],
            "detecciones": detecciones_de(sast, cwes),
        }
    if dast:
        confs["C2"] = {
            "descripcion": descripciones["C2"],
            "detecciones": detecciones_de(dast, cwes),
        }
    if sast and dast:
        confs["C3"] = {
            "descripcion": descripciones["C3"],
            "detecciones": detecciones_de(filas, cwes),
        }

    # C4 solo existe cuando la etapa 7 ya ha emitido su veredicto.
    if filas and "estado_final" in filas[0]:
        from ..cluster.clustering import ESTADOS_CONSERVADOS, veredicto

        conservados = [f for f in filas if f.get("estado_final") in ESTADOS_CONSERVADOS]
        confs["C4"] = {
            "descripcion": descripciones["C4"],
            "detecciones": detecciones_de(conservados, cwes),
        }

        # Ablaciones: aislan cada senal del filtro de C4 para poder atribuir la
        # reduccion de falsos positivos a una de las dos, en lugar de a la
        # combinacion. Se calculan con el mismo veredicto() que C4, anulando la
        # senal que no se quiere medir.
        ablaciones = {
            # Solo la alerta de ZAP: el agrupamiento no interviene.
            "C4a": ("estado_confirmacion", lambda f: veredicto(
                f.get("estado_confirmacion", ""), "no_verificable")),
            # Solo la separacion de comportamiento: la alerta no interviene.
            "C4b": ("estado_clustering", lambda f: veredicto(
                "no_verificable" if f.get("estado_confirmacion") != "observado_dast"
                else "observado_dast",
                f.get("estado_clustering", ""))),
            # Solo la regla trivial de invariancia, sin DBSCAN ni alerta.
            "C4c": ("estado_invariancia", lambda f: veredicto(
                "no_verificable" if f.get("estado_confirmacion") != "observado_dast"
                else "observado_dast",
                f.get("estado_invariancia", ""))),
        }
        # Variante fiel a Akrout et al. (2014): el agrupamiento se hace contra
        # las clases de rechazo Rr y Rii en lugar de contra la respuesta normal.
        # No es una ablacion de C4 sino un metodo alternativo, calculado sobre
        # el mismo trafico para que la comparacion sea exacta.
        if "estado_clustering_akrout" in filas[0]:
            ablaciones["C4-akrout"] = ("estado_clustering_akrout", lambda f: veredicto(
                f.get("estado_confirmacion", ""), f.get("estado_clustering_akrout", "")))
        # Regla trivial con la misma referencia que C4-akrout, pero sin DBSCAN.
        # Mide si el agrupamiento aporta algo cuando se le da la referencia de
        # rechazo "correcta" segun el articulo, no solo con la linea base normal.
        if "estado_invariancia_akrout" in filas[0]:
            ablaciones["C4-akrout-trivial"] = (
                "estado_invariancia_akrout",
                lambda f: veredicto(
                    f.get("estado_confirmacion", ""), f.get("estado_invariancia_akrout", "")
                ),
            )

        for nombre, (columna, regla) in ablaciones.items():
            if columna not in filas[0]:
                continue
            subconjunto = [f for f in filas if regla(f) in ESTADOS_CONSERVADOS]
            confs[nombre] = {
                "descripcion": descripciones.get(nombre, nombre),
                "detecciones": detecciones_de(subconjunto, cwes),
            }

    return confs


def fuente_hallazgos() -> Path:
    """Devuelve el fichero de hallazgos mas avanzado que exista.

    Permite evaluar con lo que haya: solo mapeados (C0-C3), verificados o ya
    agrupados (C4).
    """
    from ..cluster.clustering import SALIDA as FINAL
    from ..mapping.sast_to_http import SALIDA as MAPEADOS
    from ..verify.verify_with_zap import SALIDA as VERIFICADOS

    for candidato in (FINAL, VERIFICADOS, MAPEADOS):
        ruta = repo_root() / candidato
        if ruta.exists():
            return ruta
    raise RuntimeError(
        "No hay ningun fichero de hallazgos: ejecuta antes las etapas normalize y map."
    )


def escribe_resumen(filas: list[dict[str, str]]) -> dict[str, int] | None:
    """Escribe el recuento de confirmados, descartados y no verificables.

    Devuelve None si la etapa de clustering todavia no ha emitido veredicto.
    """
    if not filas or "estado_final" not in filas[0]:
        return None

    cuenta: dict[tuple[str, str], int] = {}
    totales: dict[str, int] = {}
    for fila in filas:
        estado = fila.get("estado_final", "")
        clave = (fila.get("herramienta", ""), estado)
        cuenta[clave] = cuenta.get(clave, 0) + 1
        totales[estado] = totales.get(estado, 0) + 1

    destino = repo_root() / SALIDA_RESUMEN
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(destino, "w", encoding="utf-8", newline="") as fh:
        escritor = csv.writer(fh)
        escritor.writerow(["motor", "estado", "hallazgos"])
        for (motor, estado), n in sorted(cuenta.items()):
            escritor.writerow([motor, estado, n])
        for estado, n in sorted(totales.items()):
            escritor.writerow(["TODOS", estado, n])

    print(f"Recuento de hallazgos -> {SALIDA_RESUMEN}")
    for estado, n in sorted(totales.items()):
        print(f"  {estado}: {n}")
    return totales


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("8-evaluate") as ctx:
        origen = fuente_hallazgos()
        print(f"Evaluando a partir de {origen.relative_to(repo_root())}")
        with open(origen, "r", encoding="utf-8", newline="") as fh:
            filas = list(csv.DictReader(fh))

        verdad = carga_verdad(cfg)
        cwes = cfg["evaluation"]["benchmark_cwes"]
        confs = configuraciones(filas, cfg)

        resultados = {
            nombre: evalua(datos["detecciones"], verdad, cwes) for nombre, datos in confs.items()
        }
        fp_base = resultados.get(BASE_REDUCCION_FP, {}).get("TOTAL", {}).get("FP")

        destino = repo_root() / SALIDA_METRICAS
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=COLUMNAS)
            escritor.writeheader()
            for nombre, por_cwe in resultados.items():
                for cwe, fila in por_cwe.items():
                    reduccion = ""
                    if cwe == "TOTAL" and fp_base:
                        reduccion = round((fp_base - fila["FP"]) / fp_base, 4)
                    escritor.writerow(
                        {
                            "configuracion": nombre,
                            "descripcion": confs[nombre]["descripcion"],
                            "cwe": cwe,
                            **{c: fila.get(c, "") for c in COLUMNAS if c in fila},
                            "reduccion_fp_vs_" + BASE_REDUCCION_FP: reduccion,
                        }
                    )

        escribe_resumen(filas)

        from . import figuras as modulo_figuras

        figuras = modulo_figuras.genera(cfg)

        ctx["detail"] = f"{len(confs)} configuraciones evaluadas sobre {len(verdad)} casos"

    for figura in figuras:
        print(f"Figura -> {figura.relative_to(repo_root())}")
    print(f"Metricas -> {SALIDA_METRICAS}")
    cab = f"{'config':<16}{'TP':>6}{'FP':>6}{'FN':>6}{'prec':>8}{'recall':>8}{'F1':>8}{'score':>8}"
    print(cab)
    for nombre, por_cwe in resultados.items():
        t = por_cwe["TOTAL"]
        print(
            f"{nombre:<16}{t['TP']:>6}{t['FP']:>6}{t['FN']:>6}"
            f"{t['precision']:>8.3f}{t['recall']:>8.3f}{t['f1']:>8.3f}{t['benchmark_score']:>8.3f}"
        )
