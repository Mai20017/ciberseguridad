"""Analisis de sensibilidad de los parametros del agrupamiento (etapa 7).

Responde a la objecion de que eps y min_samples se fijaron sin justificar: en vez
de defender un valor, se mide como cambia el resultado al variarlo. No genera
trafico nuevo, solo reagrupa las respuestas ya capturadas en
results/respuestas_zap.csv, por lo que una barrida completa tarda segundos.

Para cada combinacion (eps, min_samples) se repite la decision de la etapa 7, se
recompone el veredicto final y se evalua la configuracion C4 completa contra
expectedresults-1.2.csv. Se anade como referencia la regla trivial de invariancia
de la respuesta, que no tiene parametros: si C4 no mejora sobre ella en ningun
punto de la barrida, el agrupamiento no esta aportando nada y conviene decirlo.

Salida: results/sensibilidad_clustering.csv y
results/figuras/sensibilidad_eps.png
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from ..cluster.clustering import ESTADOS_CONSERVADOS, agrupa, invariancia, veredicto
from ..common import provenance
from ..common.config import repo_root
from ..evaluate.metrics import carga_verdad, detecciones_de, evalua

SALIDA = "results/sensibilidad_clustering.csv"
FIGURA = "results/figuras/sensibilidad_eps.png"

# Barrida: cubre un orden de magnitud alrededor del valor configurado (0,6).
EPS = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.8, 1.0, 1.5, 2.0]
MIN_SAMPLES = [2, 3, 5]

COLUMNAS = [
    "regla", "eps", "min_samples",
    "pares_confirmados", "pares_descartados", "pares_no_verificables",
    "TP", "FP", "FN", "TN", "precision", "recall", "f1", "benchmark_score",
    "reduccion_fp_vs_C1",
]


def _evalua_con(
    filas: list[dict[str, str]],
    decisiones: dict[tuple[str, int], str],
    verdad: dict[str, dict[str, Any]],
    cwes: list[int],
) -> dict[str, Any]:
    """Recompone el veredicto final de C4 con unas decisiones de agrupamiento dadas."""
    conservados = []
    for fila in filas:
        try:
            cwe = int(fila["cwe"])
        except (TypeError, ValueError):
            cwe = -1
        clave = (fila.get("ruta_http", ""), cwe)
        if fila["herramienta"] == "zap":
            estado_cluster = "no_verificable"
        else:
            estado_cluster = decisiones.get(clave, "no_verificable")
        if veredicto(fila.get("estado_confirmacion", ""), estado_cluster) in ESTADOS_CONSERVADOS:
            conservados.append(fila)
    return evalua(detecciones_de(conservados, set(cwes)), verdad, cwes)["TOTAL"]


def barrida(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    from ..cluster.clustering import carga_respuestas
    from ..evaluate.metrics import configuraciones, fuente_hallazgos

    with open(fuente_hallazgos(), "r", encoding="utf-8", newline="") as fh:
        filas = list(csv.DictReader(fh))
    verdad = carga_verdad(cfg)
    cwes = cfg["evaluation"]["benchmark_cwes"]
    grupos = carga_respuestas(cfg)

    # Falsos positivos de C1, que es la referencia de la reduccion declarada.
    confs = configuraciones(filas, cfg)
    fp_c1 = evalua(confs["C1"]["detecciones"], verdad, cwes)["TOTAL"]["FP"]

    salida: list[dict[str, Any]] = []

    def fila_de(regla: str, eps: Any, ms: Any, decisiones: dict[tuple[str, int], str]) -> dict[str, Any]:
        conteo = {"confirmado": 0, "descartado": 0, "no_verificable": 0}
        for estado in decisiones.values():
            conteo[estado] = conteo.get(estado, 0) + 1
        t = _evalua_con(filas, decisiones, verdad, cwes)
        return {
            "regla": regla, "eps": eps, "min_samples": ms,
            "pares_confirmados": conteo["confirmado"],
            "pares_descartados": conteo["descartado"],
            "pares_no_verificables": conteo["no_verificable"],
            "TP": t["TP"], "FP": t["FP"], "FN": t["FN"], "TN": t["TN"],
            "precision": t["precision"], "recall": t["recall"],
            "f1": t["f1"], "benchmark_score": t["benchmark_score"],
            "reduccion_fp_vs_C1": round(100 * (fp_c1 - t["FP"]) / fp_c1, 2) if fp_c1 else "",
        }

    # Referencia sin parametros: la regla trivial de invariancia.
    triviales = {c: invariancia(d["linea_base"], d["prueba_zap"])[0] for c, d in grupos.items()}
    salida.append(fila_de("invariancia (sin DBSCAN)", "", "", triviales))

    for ms in MIN_SAMPLES:
        for eps in EPS:
            local = dict(cfg)
            local["clustering"] = {**cfg["clustering"], "eps": eps, "min_samples": ms}
            decisiones = {
                c: agrupa(d["linea_base"], d["prueba_zap"], local)[0] for c, d in grupos.items()
            }
            salida.append(fila_de("DBSCAN", eps, ms, decisiones))
            print(
                f"  eps={eps:<4} min_samples={ms}  "
                f"FP={salida[-1]['FP']:<5} recall={salida[-1]['recall']:<7} "
                f"F1={salida[-1]['f1']}",
                flush=True,
            )
    return salida


def figura(filas: list[dict[str, Any]]) -> Path | None:
    """Dibuja FP y exhaustividad frente a eps, una serie por min_samples."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    from ..evaluate.figuras import (
        REJILLA, SERIE_1, SERIE_2, SERIE_3, SUPERFICIE,
        TEXTO_PRIMARIO, TEXTO_SECUNDARIO, _estilo,
    )

    dbscan = [f for f in filas if f["regla"] == "DBSCAN"]
    if not dbscan:
        return None
    colores = {2: SERIE_1, 3: SERIE_2, 5: SERIE_3}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2), dpi=200)
    fig.patch.set_facecolor(SUPERFICIE)

    for ms in sorted({f["min_samples"] for f in dbscan}):
        serie = sorted((f for f in dbscan if f["min_samples"] == ms), key=lambda f: f["eps"])
        x = [f["eps"] for f in serie]
        ax1.plot(x, [f["FP"] for f in serie], marker="o", markersize=5,
                 linewidth=2, color=colores.get(ms, SERIE_1), label=f"min_samples={ms}")
        ax2.plot(x, [f["recall"] for f in serie], marker="o", markersize=5,
                 linewidth=2, color=colores.get(ms, SERIE_1), label=f"min_samples={ms}")

    trivial = next((f for f in filas if f["regla"] != "DBSCAN"), None)
    if trivial:
        for ax, clave in ((ax1, "FP"), (ax2, "recall")):
            ax.axhline(trivial[clave], linestyle="--", linewidth=1.4, color=TEXTO_SECUNDARIO)

    ax1.set_title("Falsos positivos de C4", color=TEXTO_PRIMARIO, fontsize=11, loc="left", pad=12)
    ax2.set_title("Exhaustividad de C4", color=TEXTO_PRIMARIO, fontsize=11, loc="left", pad=12)
    for ax in (ax1, ax2):
        ax.set_xlabel("eps", color=TEXTO_SECUNDARIO)
        _estilo(ax)
        leyenda = ax.legend(frameon=False, fontsize=8)
        for texto in leyenda.get_texts():
            texto.set_color(TEXTO_SECUNDARIO)
    ax1.spines["left"].set_color(REJILLA)

    destino = repo_root() / FIGURA
    destino.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(destino, facecolor=SUPERFICIE, bbox_inches="tight")
    plt.close(fig)
    return destino


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("10-sensibilidad-clustering") as ctx:
        filas = barrida(cfg)

        destino = repo_root() / SALIDA
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=COLUMNAS)
            escritor.writeheader()
            escritor.writerows(filas)

        ruta_figura = figura(filas)

        dbscan = [f for f in filas if f["regla"] == "DBSCAN"]
        fps = {f["FP"] for f in dbscan}
        trivial = next((f for f in filas if f["regla"] != "DBSCAN"), None)

        print(f"\nSensibilidad -> {SALIDA}")
        if ruta_figura:
            print(f"Figura -> {FIGURA}")
        print(f"  combinaciones evaluadas: {len(dbscan)}")
        print(f"  valores distintos de FP en toda la barrida: {len(fps)} -> {sorted(fps)}")
        if trivial:
            print(
                f"  regla trivial de invariancia: FP={trivial['FP']} "
                f"recall={trivial['recall']} F1={trivial['f1']}"
            )
            iguales = sum(1 for f in dbscan if f["FP"] == trivial["FP"])
            print(f"  combinaciones de DBSCAN con el mismo FP que la regla trivial: {iguales}/{len(dbscan)}")

        ctx["detail"] = (
            f"{len(dbscan)} combinaciones; FP distintos={len(fps)}; "
            f"trivial FP={trivial['FP'] if trivial else '?'}"
        )
