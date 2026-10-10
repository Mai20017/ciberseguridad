"""Etapa 2: analisis estatico (SAST).

Dos motores independientes, ambos exportando SARIF:
  - Semgrep con los rulesets p/java y p/owasp-top-ten.
  - SpotBugs + FindSecBugs, usando el perfil "findsecbugs" que el propio
    pom.xml del Benchmark ya define (effort Max, threshold Low y los filtros
    de inclusion/exclusion del proyecto).

Ambos se ejecutan como contenedores hermanos lanzados contra el demonio Docker
del host, por lo que los bind mounts usan rutas del host (ver config.host_project_dir).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..common import provenance
from ..common.config import host_project_dir, repo_root
from ..common.shell import run


def _host_path(relpath: str) -> str:
    return f"{host_project_dir()}/{relpath}"


def _count_sarif_results(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return sum(len(run_.get("results", [])) for run_ in doc.get("runs", []))


def run_semgrep(cfg: dict[str, Any]) -> int:
    """Ejecuta Semgrep sobre el codigo Java del Benchmark. Devuelve nº de hallazgos."""
    sem = cfg["sast"]["semgrep"]
    image = cfg["docker"]["images"]["semgrep"]
    out_rel = sem["output_sarif"]
    out_dir = repo_root() / Path(out_rel).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    version = run(
        ["docker", "run", "--rm", image, "semgrep", "--version"], "sast-semgrep", echo=False
    ).stdout.strip()
    provenance.record_tool_version("Semgrep", version, source=image)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{_host_path(cfg['benchmark']['src_dir'])}:/src:ro",
        "-v", f"{_host_path(str(Path(out_rel).parent))}:/out",
        "-e", "SEMGREP_SEND_METRICS=off",
        image,
        "semgrep", "scan",
    ]
    for ruleset in sem["rulesets"]:
        cmd += ["--config", ruleset]
    cmd += [
        "--sarif",
        "--output", f"/out/{Path(out_rel).name}",
        "--metrics", "off",
        "--no-git-ignore",
        "--timeout", "0",
        "--max-target-bytes", "0",
        "/src/src/main/java",
    ]

    with provenance.stage("2a-sast-semgrep") as ctx:
        run(cmd, "sast-semgrep", timeout=sem["timeout_s"])
        total = _count_sarif_results(repo_root() / out_rel)
        ctx["detail"] = f"{total} hallazgos; rulesets={','.join(sem['rulesets'])}"
    print(f"Semgrep: {total} hallazgos -> {out_rel}")
    return total


def run_spotbugs(cfg: dict[str, Any]) -> int:
    """Ejecuta SpotBugs+FindSecBugs via el perfil findsecbugs del Benchmark."""
    sb = cfg["sast"]["spotbugs"]
    sarif_rel = sb["output_sarif"]
    out_dir = repo_root() / Path(sarif_rel).parent
    out_dir.mkdir(parents=True, exist_ok=True)

    provenance.record_tool_version("SpotBugs", sb["spotbugs_version"], source="pom.xml del Benchmark")
    provenance.record_tool_version(
        "FindSecBugs", sb["findsecbugs_version"], source="pom.xml del Benchmark (perfil findsecbugs)"
    )

    # Se reutiliza la imagen del Benchmark: ya contiene las clases compiladas y
    # la cache de dependencias Maven, por lo que SpotBugs analiza exactamente el
    # mismo bytecode que se esta sirviendo por HTTP.
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{_host_path(str(Path(sarif_rel).parent))}:/out",
        "-e", "MAVEN_OPTS=-Xmx4g",
        "tft-benchmark:1.2",
        # spotless:apply se omite por el mismo motivo que en la imagen: necesita
        # repositorio git y reformatearia las fuentes analizadas.
        "mvn", "-B", "-Pfindsecbugs", "-DskipTests", "-Dspotless.apply.skip=true",
        "compile",
        f"-Dspotbugs.effort={sb['effort']}",
        f"-Dspotbugs.threshold={sb['threshold']}",
        "-Dspotbugs.sarifOutput=true",
        "-Dspotbugs.sarifFullPath=true",
        "-Dspotbugs.sarifOutputDirectory=/out",
        f"-Dspotbugs.sarifOutputFilename={Path(sarif_rel).name}",
    ]

    with provenance.stage("2b-sast-spotbugs") as ctx:
        run(cmd, "sast-spotbugs", timeout=7200)
        sarif_path = repo_root() / sarif_rel
        if not sarif_path.exists():
            raise RuntimeError(
                f"SpotBugs no genero {sarif_rel}. Revisa logs/sast-spotbugs.log: "
                "puede que las propiedades -Dspotbugs.* no se hayan aplicado."
            )
        total = _count_sarif_results(sarif_path)
        ctx["detail"] = (
            f"{total} hallazgos; SpotBugs {sb['spotbugs_version']} + "
            f"FindSecBugs {sb['findsecbugs_version']}"
        )
    print(f"SpotBugs+FindSecBugs: {total} hallazgos -> {sarif_rel}")
    return total


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("2-sast") as ctx:
        semgrep_total = run_semgrep(cfg)
        spotbugs_total = run_spotbugs(cfg)
        ctx["detail"] = f"semgrep={semgrep_total}; spotbugs={spotbugs_total}"
