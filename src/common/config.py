"""Carga de la configuracion del pipeline y resolucion de rutas."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

CONFIG_RELPATH = "configs/pipeline.yml"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    cfg_path = Path(path) if path else repo_root() / CONFIG_RELPATH
    with open(cfg_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    cfg["_root"] = str(repo_root())
    return cfg


def resolve(relpath: str) -> Path:
    """Convierte una ruta del fichero de configuracion en ruta absoluta."""
    return repo_root() / relpath


def in_container() -> bool:
    """True cuando el codigo corre dentro del contenedor orquestador."""
    return os.environ.get("TFT_IN_CONTAINER") == "1"


def host_project_dir() -> str:
    """Ruta del proyecto tal como la ve el demonio Docker del host.

    Necesaria porque el orquestador lanza contenedores hermanos (Docker-outside-of-Docker):
    los bind mounts los resuelve el demonio en el host, no dentro del contenedor.
    """
    if in_container():
        value = os.environ.get("TFT_HOST_PROJECT_DIR")
        if not value:
            raise RuntimeError(
                "TFT_HOST_PROJECT_DIR no esta definida; el orquestador no puede "
                "montar rutas del host en contenedores hermanos."
            )
        return value.replace("\\", "/")
    return str(repo_root()).replace("\\", "/")


def base_url(cfg: dict[str, Any]) -> str:
    """URL del Benchmark alcanzable desde donde se esta ejecutando el codigo."""
    key = "internal_base_url" if in_container() else "host_base_url"
    return cfg["benchmark"][key]
