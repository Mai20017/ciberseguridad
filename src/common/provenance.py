"""Registro de procedencia: fecha, versiones de herramientas y tiempos por etapa.

Requisito del TFT: toda cifra publicada debe poder trazarse a una ejecucion real,
con fecha y version exacta de cada herramienta.
"""

from __future__ import annotations

import csv
import json
import platform
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import load_config, repo_root

_STAGE_CSV_HEADER = [
    "stage",
    "started_at_utc",
    "finished_at_utc",
    "duration_s",
    "status",
    "detail",
]


def _paths() -> tuple[Path, Path]:
    cfg = load_config()
    jsonl = repo_root() / cfg["paths"]["provenance_jsonl"]
    csv_path = repo_root() / cfg["paths"]["stage_times_csv"]
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    return jsonl, csv_path


def record_event(kind: str, payload: dict[str, Any]) -> None:
    jsonl, _ = _paths()
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": kind,
        **payload,
    }
    with open(jsonl, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def record_tool_version(tool: str, version: str, source: str = "") -> None:
    """Guarda la version exacta de una herramienta tal como la reporta ella misma."""
    record_event(
        "tool_version", {"tool": tool, "version": version.strip(), "source": source}
    )


def _append_stage_row(row: dict[str, Any]) -> None:
    _, csv_path = _paths()
    is_new = not csv_path.exists()
    with open(csv_path, "a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_STAGE_CSV_HEADER)
        if is_new:
            writer.writeheader()
        writer.writerow(row)


@contextmanager
def stage(name: str, detail: str = "") -> Iterator[dict[str, Any]]:
    """Mide y registra una etapa del pipeline.

    El diccionario cedido permite a la etapa anadir detalle al registro final
    (por ejemplo, numero de hallazgos producidos).
    """
    ctx: dict[str, Any] = {"detail": detail}
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    status = "ok"
    try:
        yield ctx
    except BaseException as exc:
        status = f"error: {type(exc).__name__}"
        raise
    finally:
        duration = round(time.monotonic() - t0, 2)
        finished = datetime.now(timezone.utc)
        row = {
            "stage": name,
            "started_at_utc": started.isoformat(timespec="seconds"),
            "finished_at_utc": finished.isoformat(timespec="seconds"),
            "duration_s": duration,
            "status": status,
            "detail": str(ctx.get("detail", "")),
        }
        _append_stage_row(row)
        record_event("stage", row)


def record_environment() -> None:
    """Registra el entorno de ejecucion una vez por invocacion del pipeline."""
    docker_version = ""
    try:
        docker_version = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except FileNotFoundError:
        docker_version = "docker no disponible"
    record_event(
        "environment",
        {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "docker": docker_version,
        },
    )
