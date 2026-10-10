"""Etapa 1: despliegue del OWASP Benchmark v1.2.

Clona el repositorio fijado a un commit concreto, construye la imagen Docker y
levanta Tomcat, esperando a que /benchmark/ responda antes de dar la etapa por
buena.
"""

from __future__ import annotations

import time
import urllib3
from pathlib import Path
from typing import Any

import requests

from ..common import provenance
from ..common.config import base_url, repo_root
from ..common.shell import run

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMPOSE = ["docker", "compose"]


def ensure_sources(cfg: dict[str, Any]) -> Path:
    """Garantiza que el codigo del Benchmark esta presente en el commit fijado."""
    bench = cfg["benchmark"]
    src = repo_root() / bench["src_dir"]
    commit = bench["commit"]

    if not (src / ".git").exists():
        print(f"Clonando {bench['repo_url']} en {src.name} (commit {commit[:10]})")
        src.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q", str(src)], "deploy")
        run(["git", "-C", str(src), "remote", "add", "origin", bench["repo_url"]], "deploy")
        run(["git", "-C", str(src), "fetch", "--depth", "1", "origin", commit], "deploy")
        run(["git", "-C", str(src), "checkout", "-q", "FETCH_HEAD"], "deploy")
    else:
        current = run(
            ["git", "-C", str(src), "rev-parse", "HEAD"], "deploy", echo=False
        ).stdout.strip()
        if current != commit:
            print(f"Ajustando el Benchmark al commit fijado {commit[:10]} (estaba en {current[:10]})")
            run(["git", "-C", str(src), "fetch", "--depth", "1", "origin", commit], "deploy")
            run(["git", "-C", str(src), "checkout", "-q", "FETCH_HEAD"], "deploy")

    head = run(["git", "-C", str(src), "rev-parse", "HEAD"], "deploy", echo=False).stdout.strip()
    date = run(
        ["git", "-C", str(src), "log", "-1", "--format=%cI"], "deploy", echo=False
    ).stdout.strip()
    provenance.record_tool_version(
        "OWASP Benchmark",
        f"{cfg['meta']['benchmark_version']} (commit {head}, {date})",
        source=bench["repo_url"],
    )

    expected = repo_root() / bench["expected_results_csv"]
    if not expected.exists():
        raise RuntimeError(
            f"No se encuentra {expected}; la etapa de evaluacion depende de ese fichero."
        )
    return src


def build_image(cfg: dict[str, Any]) -> None:
    print("Construyendo la imagen del Benchmark (maven + compilacion completa)")
    run(COMPOSE + ["build", "benchmark"], "deploy", timeout=3600, cwd=repo_root())
    image = run(
        ["docker", "image", "inspect", "tft-benchmark:1.2", "--format", "{{.Id}}"],
        "deploy",
        echo=False,
    ).stdout.strip()
    provenance.record_tool_version("imagen tft-benchmark", image, source="docker/benchmark.Dockerfile")
    for name, ref in (("Maven/JDK", cfg["docker"]["images"]["maven"]),):
        provenance.record_tool_version(name, ref, source="docker-compose.yml")
    provenance.record_tool_version("Tomcat", cfg["benchmark"]["tomcat_version"], source="pom.xml")


def start_container(cfg: dict[str, Any]) -> None:
    print("Levantando el contenedor del Benchmark")
    run(COMPOSE + ["up", "-d", "benchmark"], "deploy", timeout=600, cwd=repo_root())


def wait_until_ready(cfg: dict[str, Any]) -> float:
    """Espera a que el Benchmark sirva su pagina principal. Devuelve segundos."""
    url = base_url(cfg)
    timeout = cfg["benchmark"]["startup_timeout_s"]
    print(f"Esperando a {url} (maximo {timeout}s)")
    t0 = time.monotonic()
    last = ""
    while time.monotonic() - t0 < timeout:
        try:
            resp = requests.get(url, verify=False, timeout=10)
            if resp.status_code == 200:
                elapsed = round(time.monotonic() - t0, 1)
                print(f"Benchmark operativo en {elapsed}s ({len(resp.content)} bytes)")
                return elapsed
            last = f"HTTP {resp.status_code}"
        except requests.RequestException as exc:
            last = type(exc).__name__
        time.sleep(5)
    raise RuntimeError(
        f"El Benchmark no respondio en {timeout}s (ultimo estado: {last}). "
        f"Revisa: docker compose logs benchmark"
    )


def count_test_cases(cfg: dict[str, Any]) -> int:
    src_root = repo_root() / cfg["benchmark"]["java_src_root"]
    return len(list(src_root.glob("BenchmarkTest*.java")))


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("1-deploy") as ctx:
        ensure_sources(cfg)
        build_image(cfg)
        start_container(cfg)
        elapsed = wait_until_ready(cfg)
        cases = count_test_cases(cfg)
        ctx["detail"] = f"{cases} casos de prueba; arranque {elapsed}s; url={base_url(cfg)}"
        print(f"Casos de prueba en el Benchmark: {cases}")
