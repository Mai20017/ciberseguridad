"""Genera results/entorno.txt: versiones, fecha, hardware y tiempo por etapa.

Alimenta el apartado 4.1 de la memoria. Todo se lee de lo que las propias
herramientas reportaron durante la ejecucion (results/provenance.jsonl) y de
los tiempos medidos (results/stage_times.csv): este fichero no declara ninguna
version que no se haya observado.
"""

from __future__ import annotations

import csv
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_config, repo_root

SALIDA = "results/entorno.txt"


def _lee_primero(ruta: str, prefijo: str) -> str:
    try:
        for linea in Path(ruta).read_text(encoding="utf-8", errors="replace").splitlines():
            if linea.strip().startswith(prefijo):
                return linea.split(":", 1)[1].strip()
    except OSError:
        pass
    return "no disponible"


def _hardware() -> dict[str, str]:
    cpu = _lee_primero("/proc/cpuinfo", "model name")
    mem_kb = _lee_primero("/proc/meminfo", "MemTotal").replace("kB", "").strip()
    try:
        mem = f"{int(mem_kb) / 1024 / 1024:.1f} GiB"
    except ValueError:
        mem = "no disponible"
    nucleos = str(len(__import__("os").sched_getaffinity(0))) if hasattr(__import__("os"), "sched_getaffinity") else "?"
    return {"cpu": cpu, "nucleos_disponibles": nucleos, "memoria": mem}


def _docker() -> dict[str, str]:
    def salida(*cmd: str) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout.strip()
        except FileNotFoundError:
            return "no disponible"

    return {
        "servidor": salida("docker", "version", "--format", "{{.Server.Version}}"),
        "cliente": salida("docker", "version", "--format", "{{.Client.Version}}"),
        "so_anfitrion": salida("docker", "info", "--format", "{{.OperatingSystem}}"),
    }


def _versiones(cfg: dict[str, Any]) -> list[tuple[str, str, str]]:
    ruta = repo_root() / cfg["paths"]["provenance_jsonl"]
    vistas: dict[str, tuple[str, str]] = {}
    if ruta.exists():
        with open(ruta, "r", encoding="utf-8") as fh:
            for linea in fh:
                try:
                    evento = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                if evento.get("kind") == "tool_version":
                    vistas[evento["tool"]] = (evento.get("version", ""), evento.get("source", ""))
    return [(nombre, v, s) for nombre, (v, s) in sorted(vistas.items())]


def _tiempos(cfg: dict[str, Any]) -> tuple[list[dict[str, str]], int]:
    """Devuelve la ultima ejecucion correcta de cada etapa y los intentos fallidos.

    stage_times.csv se escribe en modo anexo, por lo que acumula el historico
    completo. Para el apartado 4.1 interesa el tiempo de la ejecucion valida de
    cada etapa; los intentos fallidos se cuentan aparte y siguen disponibles en
    provenance.jsonl.
    """
    ruta = repo_root() / cfg["paths"]["stage_times_csv"]
    if not ruta.exists():
        return [], 0

    with open(ruta, "r", encoding="utf-8", newline="") as fh:
        historico = list(csv.DictReader(fh))

    ultimas: dict[str, dict[str, str]] = {}
    fallidos = 0
    for fila in historico:
        if fila.get("status") == "ok":
            ultimas[fila["stage"]] = fila
        else:
            fallidos += 1
    return [ultimas[k] for k in sorted(ultimas)], fallidos


def genera(cfg: dict[str, Any] | None = None) -> Path:
    cfg = cfg or load_config()
    hw = _hardware()
    dk = _docker()
    lineas: list[str] = []

    lineas.append("ENTORNO DE EJECUCION DEL PIPELINE SAST + DAST")
    lineas.append("=" * 62)
    lineas.append("")
    lineas.append(f"Generado: {datetime.now(timezone.utc).isoformat(timespec='seconds')} (UTC)")
    lineas.append(f"Proyecto: {cfg['meta']['project']}")
    lineas.append(f"Aplicacion evaluada: OWASP Benchmark v{cfg['meta']['benchmark_version']}")
    lineas.append("")

    lineas.append("HARDWARE")
    lineas.append("-" * 62)
    lineas.append(f"CPU:                  {hw['cpu']}")
    lineas.append(f"Nucleos disponibles:  {hw['nucleos_disponibles']}")
    lineas.append(f"Memoria disponible:   {hw['memoria']}")
    lineas.append("Nota: son los recursos que el motor de Docker expone al pipeline,")
    lineas.append("      que son los que realmente limitaron la ejecucion.")
    lineas.append("")

    lineas.append("PLATAFORMA")
    lineas.append("-" * 62)
    lineas.append(f"Python:               {platform.python_version()}")
    lineas.append(f"Nucleo:               {platform.platform()}")
    lineas.append(f"Docker (servidor):    {dk['servidor']}")
    lineas.append(f"Docker (cliente):     {dk['cliente']}")
    lineas.append(f"SO anfitrion:         {dk['so_anfitrion']}")
    lineas.append("")

    lineas.append("VERSIONES DE LAS HERRAMIENTAS")
    lineas.append("-" * 62)
    lineas.append("Tal como cada herramienta se identifico durante la ejecucion.")
    lineas.append("")
    for nombre, version, fuente in _versiones(cfg):
        lineas.append(f"{nombre}")
        lineas.append(f"    version: {version}")
        if fuente:
            lineas.append(f"    fuente:  {fuente}")
    lineas.append("")

    lineas.append("IMAGENES DOCKER FIJADAS")
    lineas.append("-" * 62)
    for clave, imagen in sorted(cfg["docker"]["images"].items()):
        lineas.append(f"{clave:<12} {imagen}")
    lineas.append("")

    etapas, fallidos = _tiempos(cfg)
    lineas.append("TIEMPO POR ETAPA")
    lineas.append("-" * 62)
    lineas.append("Ultima ejecucion correcta de cada etapa.")
    lineas.append("")
    lineas.append(f"{'etapa':<34}{'segundos':>10}{'minutos':>10}")
    total = 0.0
    for fila in etapas:
        try:
            segundos = float(fila["duration_s"])
        except (KeyError, ValueError):
            segundos = 0.0
        total += segundos
        lineas.append(f"{fila['stage']:<34}{segundos:>10.1f}{segundos / 60:>10.1f}")
    lineas.append("-" * 62)
    lineas.append(f"{'TOTAL':<34}{total:>10.1f}{total / 60:>10.1f}")
    lineas.append("")
    lineas.append("Las sub-etapas (2a, 2b, 3b, 3c...) estan incluidas dentro del tiempo de")
    lineas.append("su etapa principal, por lo que el TOTAL las cuenta dos veces.")
    if any(f["stage"].startswith("9-") for f in etapas):
        lineas.append("La etapa 9 no forma parte del pipeline: es la validacion externa de las")
        lineas.append("metricas con el scorer oficial del Benchmark y se lanza aparte.")
    if fallidos:
        lineas.append(
            f"Hay {fallidos} intentos fallidos registrados en provenance.jsonl, "
            "excluidos de esta tabla."
        )
    lineas.append("")

    lineas.append("CONFIGURACION RELEVANTE DEL EXPERIMENTO")
    lineas.append("-" * 62)
    bench = cfg["benchmark"]
    lineas.append(f"Commit del Benchmark:     {bench['commit']}")
    lineas.append(f"Casos de prueba:          2740 ({bench['expected_results_csv']})")
    lineas.append(f"CWE evaluados:            {cfg['evaluation']['benchmark_cwes']}")
    lineas.append(f"CWE excluidos:            {cfg['evaluation']['excluded_cwes']} (sin casos en el Benchmark)")
    lineas.append(f"CWE no verificables DAST: {cfg['cwes_no_verificables_por_dast']}")
    z = cfg["dast"]["zap"]
    lineas.append(f"ZAP, politica de escaneo: St-{z['attack_strength'][:3].title()}-Th-{z['alert_threshold'][:3].title()}")
    lineas.append(f"ZAP, inyeccion cabeceras: {z['inject_headers']}")
    lineas.append(f"ZAP, inyeccion cookies:   {z['inject_cookies']}")
    lineas.append(f"Semgrep, rulesets:        {', '.join(cfg['sast']['semgrep']['rulesets'])}")
    lineas.append("")

    destino = repo_root() / SALIDA
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return destino
