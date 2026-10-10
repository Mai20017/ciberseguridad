"""Genera las figuras de results/figuras/ a partir de results/metrics.csv.

Dos figuras, ambas sobre la fila TOTAL de cada configuracion:
  - precision, recall y F1 por configuracion (barras agrupadas);
  - Benchmark Score (TPR - FPR) por configuracion.

Las barras llevan etiqueta de valor visible: ademas de facilitar la lectura en
papel, cubre el requisito de relieve de la paleta, porque uno de los tres tonos
queda por debajo de 3:1 de contraste sobre fondo claro.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ..common.config import repo_root

DIRECTORIO = "results/figuras"

# Paleta categorica validada (slots 1-3), modo claro
SERIE_1 = "#2a78d6"  # azul
SERIE_2 = "#eb6834"  # naranja
SERIE_3 = "#1baf7a"  # aqua

TEXTO_PRIMARIO = "#0b0b0b"
TEXTO_SECUNDARIO = "#52514e"
SUPERFICIE = "#fcfcfb"
REJILLA = "#dedcd5"

ORDEN = [
    "C0-semgrep", "C0-spotbugs", "C0-zap", "C1", "C2", "C3", "C4",
    # Ablaciones de C4, al final para que no rompan la lectura de C0-C4.
    "C4a", "C4b", "C4c", "C4-akrout", "C4-akrout-trivial",
]


def _estilo(ax: Any) -> None:
    ax.set_facecolor(SUPERFICIE)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(REJILLA)
    ax.spines["bottom"].set_color(REJILLA)
    ax.tick_params(colors=TEXTO_SECUNDARIO, length=0)
    ax.yaxis.grid(True, color=REJILLA, linewidth=0.8)
    ax.set_axisbelow(True)


def carga_totales(ruta: Path) -> list[dict[str, Any]]:
    """Lee la fila TOTAL de cada configuracion de metrics.csv."""
    with open(ruta, "r", encoding="utf-8", newline="") as fh:
        filas = [f for f in csv.DictReader(fh) if f["cwe"] == "TOTAL"]

    def clave(f: dict[str, str]) -> int:
        nombre = f["configuracion"]
        return ORDEN.index(nombre) if nombre in ORDEN else len(ORDEN)

    return sorted(filas, key=clave)


def figura_metricas(totales: list[dict[str, Any]], destino: Path) -> Path:
    etiquetas = [f["configuracion"] for f in totales]
    series = [
        ("Precision", [float(f["precision"]) for f in totales], SERIE_1),
        ("Recall", [float(f["recall"]) for f in totales], SERIE_2),
        ("F1", [float(f["f1"]) for f in totales], SERIE_3),
    ]

    n = len(series)
    ancho = 0.26
    posiciones = range(len(etiquetas))

    fig, ax = plt.subplots(figsize=(max(8.0, 1.5 * len(etiquetas)), 4.8), dpi=200)
    fig.patch.set_facecolor(SUPERFICIE)

    for i, (nombre, valores, color) in enumerate(series):
        desplazamiento = (i - (n - 1) / 2) * (ancho + 0.015)
        x = [p + desplazamiento for p in posiciones]
        ax.bar(x, valores, width=ancho, label=nombre, color=color, edgecolor=SUPERFICIE, linewidth=1.2)
        for xi, valor in zip(x, valores):
            ax.text(
                xi, valor + 0.018, f"{valor:.3f}",
                ha="center", va="bottom", fontsize=7, color=TEXTO_SECUNDARIO,
            )

    ax.set_xticks(list(posiciones))
    ax.set_xticklabels(etiquetas, color=TEXTO_PRIMARIO)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("", color=TEXTO_SECUNDARIO)
    ax.set_title(
        "Precision, recall y F1 por configuracion",
        color=TEXTO_PRIMARIO, fontsize=12, loc="left", pad=14,
    )
    _estilo(ax)
    leyenda = ax.legend(frameon=False, ncol=3, loc="upper left", bbox_to_anchor=(0, 1.02), fontsize=9)
    for texto in leyenda.get_texts():
        texto.set_color(TEXTO_SECUNDARIO)

    fig.tight_layout()
    fig.savefig(destino, facecolor=SUPERFICIE, bbox_inches="tight")
    plt.close(fig)
    return destino


def figura_benchmark_score(totales: list[dict[str, Any]], destino: Path) -> Path:
    etiquetas = [f["configuracion"] for f in totales]
    valores = [float(f["benchmark_score"]) for f in totales]

    fig, ax = plt.subplots(figsize=(max(8.0, 1.5 * len(etiquetas)), 4.4), dpi=200)
    fig.patch.set_facecolor(SUPERFICIE)

    ax.bar(etiquetas, valores, width=0.5, color=SERIE_1, edgecolor=SUPERFICIE, linewidth=1.2)
    for x, valor in zip(etiquetas, valores):
        ax.text(
            x, valor + 0.012, f"{valor:.3f}",
            ha="center", va="bottom", fontsize=8, color=TEXTO_SECUNDARIO,
        )

    ax.set_ylim(0, max(valores + [0.1]) * 1.18)
    ax.set_title(
        "Benchmark Score (TPR - FPR) por configuracion",
        color=TEXTO_PRIMARIO, fontsize=12, loc="left", pad=14,
    )
    ax.tick_params(axis="x", colors=TEXTO_PRIMARIO)
    _estilo(ax)

    fig.tight_layout()
    fig.savefig(destino, facecolor=SUPERFICIE, bbox_inches="tight")
    plt.close(fig)
    return destino


def genera(cfg: dict[str, Any]) -> list[Path]:
    from .metrics import SALIDA_METRICAS

    origen = repo_root() / SALIDA_METRICAS
    if not origen.exists():
        raise RuntimeError(f"No existe {SALIDA_METRICAS}: ejecuta antes la etapa evaluate.")

    totales = carga_totales(origen)
    if not totales:
        raise RuntimeError("metrics.csv no contiene filas TOTAL")

    directorio = repo_root() / DIRECTORIO
    directorio.mkdir(parents=True, exist_ok=True)
    return [
        figura_metricas(totales, directorio / "precision_recall_f1_por_configuracion.png"),
        figura_benchmark_score(totales, directorio / "benchmark_score_por_configuracion.png"),
    ]
