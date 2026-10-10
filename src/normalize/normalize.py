"""Etapa 4: normalizacion de los hallazgos a un esquema comun.

Las tres herramientas describen un hallazgo de forma distinta:
  - Semgrep (SARIF): no pone "level" en el resultado, hay que tomarlo del
    defaultConfiguration de la regla; el CWE va en las etiquetas de la regla.
  - SpotBugs (SARIF): si trae "level" en el resultado, y el CWE va en la
    taxonomia CWE declarada en "relationships".
  - ZAP (JSON de su API): trae cweid, riesgo, URL y parametro, pero ningun
    fichero ni linea.

El esquema comun es el que pide el TFT: herramienta, CWE, archivo, linea,
ruta_http, parametro y severidad, mas las columnas necesarias para las etapas
posteriores (caso de prueba, vector de entrada, regla y si el CWE esta en el
ambito del Benchmark).
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from ..common import provenance
from ..common.config import repo_root

SCHEMA = [
    "id",
    "herramienta",
    "cwe",
    "cwe_reportado",
    "caso",
    "archivo",
    "linea",
    "ruta_http",
    "parametro",
    "vector",
    "severidad",
    "regla",
    "en_ambito",
]

SALIDA = "results/hallazgos_normalizados.csv"

_CASO = re.compile(r"(BenchmarkTest\d{5})")

# SARIF level -> escala comun
_NIVEL_SARIF = {"error": "alta", "warning": "media", "note": "baja", "none": "informativa"}
# riesgo de ZAP -> escala comun
_RIESGO_ZAP = {
    "High": "alta",
    "Medium": "media",
    "Low": "baja",
    "Informational": "informativa",
}


def _id(fila: dict[str, Any]) -> str:
    clave = "|".join(
        str(fila.get(c, "")) for c in ("herramienta", "regla", "archivo", "linea", "ruta_http", "parametro")
    )
    return hashlib.sha1(clave.encode("utf-8")).hexdigest()[:16]


def _caso_de(texto: str) -> str:
    m = _CASO.search(texto or "")
    return m.group(1) if m else ""


def _ruta_proyecto(uri: str) -> str:
    """Normaliza la ruta de un fichero a una ruta relativa al proyecto.

    Semgrep informa rutas absolutas del contenedor (/src/src/main/java/...),
    SpotBugs las informa ya relativas (src/main/java/...).
    """
    uri = (uri or "").replace("\\", "/")
    for prefijo in ("file:///", "file://", "/src/", "src/"):
        if uri.startswith(prefijo):
            uri = uri[len(prefijo):]
            if prefijo in ("/src/", "src/"):
                uri = "src/" + uri if not uri.startswith("src/") else uri
            break
    idx = uri.find("src/main/java/")
    return uri[idx:] if idx >= 0 else uri


def normaliza_cwe(cwe: int | None, cfg: dict[str, Any]) -> int | None:
    """Aplica la tabla de equivalencias de CWE del fichero de configuracion."""
    if cwe is None:
        return None
    return cfg.get("cwe_equivalences", {}).get(cwe, cwe)


def carga_semgrep(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    ruta = repo_root() / cfg["sast"]["semgrep"]["output_sarif"]
    doc = json.loads(ruta.read_text(encoding="utf-8"))
    filas = []
    for run in doc.get("runs", []):
        reglas = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for res in run.get("results", []):
            regla = reglas.get(res.get("ruleId"), {})
            cwe = None
            for etiqueta in regla.get("properties", {}).get("tags", []):
                m = re.match(r"CWE-(\d+)", etiqueta)
                if m:
                    cwe = int(m.group(1))
                    break
            nivel = res.get("level") or regla.get("defaultConfiguration", {}).get("level", "warning")
            loc = res["locations"][0]["physicalLocation"]
            archivo = _ruta_proyecto(loc["artifactLocation"]["uri"])
            filas.append(
                {
                    "herramienta": "semgrep",
                    "cwe_reportado": cwe,
                    "cwe": normaliza_cwe(cwe, cfg),
                    "caso": _caso_de(archivo),
                    "archivo": archivo,
                    "linea": loc.get("region", {}).get("startLine"),
                    "ruta_http": "",
                    "parametro": "",
                    "vector": "",
                    "severidad": _NIVEL_SARIF.get(nivel, nivel),
                    "regla": res.get("ruleId", ""),
                }
            )
    return filas


def carga_spotbugs(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    ruta = repo_root() / cfg["sast"]["spotbugs"]["output_sarif"]
    doc = json.loads(ruta.read_text(encoding="utf-8"))
    filas = []
    for run in doc.get("runs", []):
        reglas = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for res in run.get("results", []):
            regla = reglas.get(res.get("ruleId"), {})
            cwe = None
            for rel in regla.get("relationships", []):
                destino = rel.get("target", {})
                if destino.get("toolComponent", {}).get("name") == "CWE":
                    try:
                        cwe = int(destino["id"])
                    except (KeyError, ValueError):
                        cwe = None
                    break
            loc = res["locations"][0]["physicalLocation"]
            archivo = _ruta_proyecto(loc["artifactLocation"]["uri"])
            filas.append(
                {
                    "herramienta": "spotbugs",
                    "cwe_reportado": cwe,
                    "cwe": normaliza_cwe(cwe, cfg),
                    "caso": _caso_de(archivo),
                    "archivo": archivo,
                    "linea": loc.get("region", {}).get("startLine"),
                    "ruta_http": "",
                    "parametro": "",
                    "vector": "",
                    "severidad": _NIVEL_SARIF.get(res.get("level", "warning"), "media"),
                    "regla": res.get("ruleId", ""),
                }
            )
    return filas


def carga_zap(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    ruta = repo_root() / cfg["dast"]["zap"]["output_json"]
    if not ruta.exists():
        raise RuntimeError(f"No existe {ruta}: ejecuta antes la etapa dast.")
    doc = json.loads(ruta.read_text(encoding="utf-8"))
    filas = []
    for alerta in doc.get("alerts", []):
        try:
            cwe = int(alerta.get("cweid", ""))
        except (TypeError, ValueError):
            cwe = None
        if cwe is not None and cwe < 0:
            cwe = None
        url = alerta.get("url", "")
        filas.append(
            {
                "herramienta": "zap",
                "cwe_reportado": cwe,
                "cwe": normaliza_cwe(cwe, cfg),
                "caso": _caso_de(url),
                "archivo": "",
                "linea": "",
                "ruta_http": urlparse(url).path,
                "parametro": alerta.get("param", ""),
                "vector": "",
                "severidad": _RIESGO_ZAP.get(alerta.get("risk", ""), "informativa"),
                "regla": f"{alerta.get('pluginId', '')}:{alerta.get('name', '')}",
            }
        )
    return filas


def escribe(filas: Iterable[dict[str, Any]], destino: Path) -> int:
    destino.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with open(destino, "w", encoding="utf-8", newline="") as fh:
        escritor = csv.DictWriter(fh, fieldnames=SCHEMA)
        escritor.writeheader()
        for fila in filas:
            fila["id"] = _id(fila)
            escritor.writerow({c: fila.get(c, "") for c in SCHEMA})
            total += 1
    return total


def run_stage(cfg: dict[str, Any]) -> None:
    ambito = set(cfg["evaluation"]["benchmark_cwes"])
    with provenance.stage("4-normalize") as ctx:
        filas = carga_semgrep(cfg) + carga_spotbugs(cfg) + carga_zap(cfg)
        for fila in filas:
            fila["en_ambito"] = fila["cwe"] in ambito

        destino = repo_root() / SALIDA
        total = escribe(filas, destino)

        por_herramienta: dict[str, int] = {}
        en_ambito = 0
        for fila in filas:
            por_herramienta[fila["herramienta"]] = por_herramienta.get(fila["herramienta"], 0) + 1
            en_ambito += bool(fila["en_ambito"])
        ctx["detail"] = f"{total} hallazgos ({por_herramienta}); {en_ambito} en ambito"

    print(f"Normalizados {total} hallazgos -> {SALIDA}")
    for herramienta, n in sorted(por_herramienta.items()):
        print(f"  {herramienta}: {n}")
    print(f"  en los 11 CWE del Benchmark: {en_ambito}")
