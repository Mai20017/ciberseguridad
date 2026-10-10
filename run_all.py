#!/usr/bin/env python3
"""Orquestador del pipeline SAST+DAST sobre OWASP Benchmark v1.2.

Uso tipico (dentro del contenedor orquestador):
    python run_all.py --stages deploy,sast
    python run_all.py --all
"""

from __future__ import annotations

import argparse
import sys

from src.cluster import clustering
from src.common import entorno, provenance
from src.common.config import load_config
from src.dast import run_zap
from src.deploy import deploy_benchmark
from src.mapping import sast_to_http
from src.evaluate import metrics
from src.normalize import normalize
from src.sast import run_sast
from src.evaluate import carga_revision
from src.report import informe
from src.validate import scorer_oficial, sensibilidad
from src.verify import verify_with_zap

STAGES = {
    "deploy": ("1. Despliegue del Benchmark", deploy_benchmark.run_stage),
    "sast": ("2. Analisis estatico (Semgrep + SpotBugs/FindSecBugs)", run_sast.run_stage),
    "dast": ("3. Analisis dinamico (OWASP ZAP)", run_zap.run_stage),
    "normalize": ("4. Normalizacion al esquema comun", normalize.run_stage),
    "map": ("5. Mapeo SAST -> ruta HTTP y parametro", sast_to_http.run_stage),
    "verify": ("6. Verificacion dirigida con ZAP", verify_with_zap.run_stage),
    "cluster": ("7. Clustering de respuestas HTTP contra la linea base", clustering.run_stage),
    "evaluate": ("8. Evaluacion contra expectedresults-1.2.csv", metrics.run_stage),
    "informe": ("9. Informe final legible y lista de trabajo", informe.run_stage),
}

# Comprobacion externa, no es una etapa del pipeline: contrasta las metricas de
# la etapa 8 con el scorer oficial de OWASP Benchmark. Queda fuera de --all
# porque no produce resultados propios, solo verifica los ya producidos.
EXTRAS = {
    "validate": (
        "Validacion de las metricas con el scorer oficial (BenchmarkUtils)",
        scorer_oficial.run_stage,
    ),
    "sensibilidad": (
        "Sensibilidad de eps y min_samples del agrupamiento",
        sensibilidad.run_stage,
    ),
    "carga": (
        "Carga de revision manual sobre el informe completo",
        carga_revision.run_stage,
    ),
}

PENDING: list[str] = []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--stages",
        help="Etapas separadas por coma. Disponibles: " + ", ".join({**STAGES, **EXTRAS}),
    )
    parser.add_argument("--all", action="store_true", help="Ejecuta todas las etapas implementadas")
    parser.add_argument("--list", action="store_true", help="Lista las etapas y termina")
    args = parser.parse_args(argv)

    if args.list:
        for key, (title, _) in STAGES.items():
            print(f"  {key:<10} {title}")
        for key, (title, _) in EXTRAS.items():
            print(f"  {key:<10} {title} [no incluida en --all]")
        for key in PENDING:
            print(f"  {key:<10} (pendiente de implementar)")
        return 0

    if args.all:
        selected = list(STAGES)
    elif args.stages:
        selected = [s.strip() for s in args.stages.split(",") if s.strip()]
    else:
        parser.error("Indica --stages, --all o --list")

    disponibles = {**STAGES, **EXTRAS}
    unknown = [s for s in selected if s not in disponibles]
    if unknown:
        pending = [s for s in unknown if s in PENDING]
        if pending:
            parser.error(f"Etapas todavia no implementadas: {', '.join(pending)}")
        parser.error(f"Etapas desconocidas: {', '.join(unknown)}")

    cfg = load_config()
    provenance.record_environment()

    for key in selected:
        title, func = disponibles[key]
        print(f"\n=== {title} ===", flush=True)
        func(cfg)

    ruta_entorno = entorno.genera(cfg)
    print("\nEtapas completadas:", ", ".join(selected))
    print(f"Versiones, hardware y tiempos por etapa en {ruta_entorno.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
