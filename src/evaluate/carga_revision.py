"""Carga de revision manual sobre el informe completo que recibe el auditor.

results/metrics.csv mide el filtro sobre los pares puntuables del Benchmark, que
es lo correcto para comparar con el scorer oficial, pero no es lo que llega a la
mesa de un auditor. El problema que motiva el trabajo es el coste de revisar, y
ese coste se paga sobre *todos* los hallazgos del informe, incluidos:

  - los hallazgos cuyo CWE queda fuera de las 11 categorias del Benchmark, que
    el Benchmark no puntua pero que el auditor si tiene que leer;
  - los hallazgos SAST cuyo CWE no coincide con el de la categoria de su caso,
    que tampoco entran en la puntuacion por categoria.

Este modulo mide las dos cosas por separado y para cada configuracion:

  - hallazgos entregados: filas del informe, que es el volumen bruto;
  - items a revisar: tripletas (archivo, linea, CWE) distintas, que es una
    aproximacion mas honesta al trabajo real, porque varios avisos sobre la
    misma linea y el mismo tipo de fallo son un unico item de triaje.

Salida: results/carga_revision.csv
"""

from __future__ import annotations

import csv
from typing import Any

from ..common import provenance
from ..common.config import repo_root
from .metrics import carga_verdad, fuente_hallazgos

SALIDA = "results/carga_revision.csv"

COLUMNAS = [
    "configuracion",
    "hallazgos_entregados",
    "items_distintos",
    "items_agrupando_dast_por_regla",
    "en_ambito_y_de_su_categoria",
    "en_ambito_pero_de_otra_categoria",
    "cwe_fuera_del_ambito",
    "reduccion_items_vs_C1_pct",
    "reduccion_items_agrupados_vs_C1_pct",
]


def _clasifica(fila: dict[str, str], cwes: set[int], verdad: dict[str, dict[str, Any]]) -> str:
    try:
        cwe = int(fila["cwe"])
    except (TypeError, ValueError):
        return "fuera"
    if cwe not in cwes:
        return "fuera"
    caso = fila.get("caso", "")
    if caso in verdad and verdad[caso]["cwe"] == cwe:
        return "puntuable"
    return "otra_categoria"


def _item(fila: dict[str, str]) -> tuple[str, ...]:
    """Unidad de triaje: un sitio concreto y un tipo de fallo.

    Para un hallazgo SAST el sitio es (archivo, linea); para uno de ZAP no hay
    fichero ni linea, asi que es (ruta HTTP, parametro). Usar (archivo, linea)
    para todo colapsaria los 16.251 avisos de ZAP en tantos items como CWE
    distintos, que subestima su coste de revision de forma grosera.
    """
    if fila.get("herramienta") == "zap":
        return ("zap", fila.get("ruta_http", ""), fila.get("parametro", ""), fila.get("cwe", ""))
    return ("sast", fila.get("archivo", ""), fila.get("linea", ""), fila.get("cwe", ""))


def _item_agrupado(fila: dict[str, str]) -> tuple[str, ...]:
    """Cota inferior de la carga: los avisos de ZAP agrupados por regla.

    La interfaz de ZAP presenta sus alertas agrupadas por regla, con las URLs
    afectadas como instancias dentro de cada una. Un auditor que trabaje asi no
    revisa 10.238 items de ZAP, sino unas pocas decenas. La cota de _item() y
    esta acotan el coste real por arriba y por abajo, y conviene dar las dos en
    lugar de elegir la que mas convenga.
    """
    if fila.get("herramienta") == "zap":
        return ("zap", fila.get("regla", ""), fila.get("cwe", ""))
    return ("sast", fila.get("archivo", ""), fila.get("linea", ""), fila.get("cwe", ""))


def calcula(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    from ..cluster.clustering import ESTADOS_CONSERVADOS

    with open(fuente_hallazgos(), "r", encoding="utf-8", newline="") as fh:
        filas = list(csv.DictReader(fh))
    cwes = set(cfg["evaluation"]["benchmark_cwes"])
    verdad = carga_verdad(cfg)

    sast = [f for f in filas if f["herramienta"] in ("semgrep", "spotbugs")]
    dast = [f for f in filas if f["herramienta"] == "zap"]

    conjuntos: dict[str, list[dict[str, str]]] = {
        "C0-semgrep": [f for f in filas if f["herramienta"] == "semgrep"],
        "C0-spotbugs": [f for f in filas if f["herramienta"] == "spotbugs"],
        "C0-zap": dast,
        "C1": sast,
        "C2": dast,
        "C3": filas,
    }
    if filas and "estado_final" in filas[0]:
        conjuntos["C4"] = [f for f in filas if f.get("estado_final") in ESTADOS_CONSERVADOS]

    base_items: int | None = None
    base_agr: int | None = None
    salida: list[dict[str, Any]] = []
    for nombre, subconjunto in conjuntos.items():
        clases = {"puntuable": 0, "otra_categoria": 0, "fuera": 0}
        for fila in subconjunto:
            clases[_clasifica(fila, cwes, verdad)] += 1
        items = len({_item(f) for f in subconjunto})
        items_agr = len({_item_agrupado(f) for f in subconjunto})
        if nombre == "C1":
            base_items = items
            base_agr = items_agr
        salida.append(
            {
                "configuracion": nombre,
                "hallazgos_entregados": len(subconjunto),
                "items_distintos": items,
                "items_agrupando_dast_por_regla": items_agr,
                "en_ambito_y_de_su_categoria": clases["puntuable"],
                "en_ambito_pero_de_otra_categoria": clases["otra_categoria"],
                "cwe_fuera_del_ambito": clases["fuera"],
                "reduccion_items_vs_C1_pct": "",
                "reduccion_items_agrupados_vs_C1_pct": "",
            }
        )

    if base_items:
        for fila in salida:
            fila["reduccion_items_vs_C1_pct"] = round(
                100 * (base_items - fila["items_distintos"]) / base_items, 2
            )
    if base_agr:
        for fila in salida:
            fila["reduccion_items_agrupados_vs_C1_pct"] = round(
                100 * (base_agr - fila["items_agrupando_dast_por_regla"]) / base_agr, 2
            )
    return salida


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("11-carga-revision") as ctx:
        filas = calcula(cfg)
        destino = repo_root() / SALIDA
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=COLUMNAS)
            escritor.writeheader()
            escritor.writerows(filas)

        print(f"Carga de revision -> {SALIDA}")
        print(
            f"{'config':<14}{'entregados':>12}{'items':>9}{'items agr.':>12}"
            f"{'puntuables':>12}{'fuera':>8}{'red.%':>8}{'red.agr.%':>11}"
        )
        for f in filas:
            print(
                f"{f['configuracion']:<14}{f['hallazgos_entregados']:>12}"
                f"{f['items_distintos']:>9}{f['items_agrupando_dast_por_regla']:>12}"
                f"{f['en_ambito_y_de_su_categoria']:>12}"
                f"{f['cwe_fuera_del_ambito']:>8}{f['reduccion_items_vs_C1_pct']:>8}"
                f"{f['reduccion_items_agrupados_vs_C1_pct']:>11}"
            )
        c4 = next((f for f in filas if f["configuracion"] == "C4"), None)
        if c4:
            ctx["detail"] = (
                f"C4 entrega {c4['hallazgos_entregados']} hallazgos "
                f"({c4['items_distintos']} items distintos); "
                f"reduccion de items vs C1 {c4['reduccion_items_vs_C1_pct']}%"
            )
