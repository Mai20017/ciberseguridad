"""Ejecucion de procesos externos con log a fichero."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Sequence

from .config import load_config, repo_root


def log_path(name: str) -> Path:
    cfg = load_config()
    logs = repo_root() / cfg["paths"]["logs_dir"]
    logs.mkdir(parents=True, exist_ok=True)
    return logs / f"{name}.log"


def run(
    cmd: Sequence[str],
    log_name: str,
    check: bool = True,
    timeout: int | None = None,
    cwd: Path | None = None,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Lanza un comando, vuelca su salida a logs/<log_name>.log y la devuelve."""
    if echo:
        print(f"  $ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
    )
    out = log_path(log_name)
    with open(out, "a", encoding="utf-8") as fh:
        fh.write(f"\n$ {' '.join(cmd)}\n")
        fh.write(proc.stdout or "")
        fh.write(proc.stderr or "")
    if check and proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-40:])
        print(tail, file=sys.stderr)
        raise RuntimeError(
            f"Comando fallido (codigo {proc.returncode}): {' '.join(cmd)}\n"
            f"Log completo: {out}"
        )
    return proc
