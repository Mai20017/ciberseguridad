"""Etapa 5: mapeo de cada hallazgo SAST a su ruta HTTP, parametro y vector.

La fuente del mapeo es `data/benchmark-crawler-http.xml`, el fichero que el
propio Benchmark usa para recorrer sus casos de prueba. Contiene, por cada
BenchmarkTestNNNNN, su URL y el vector exacto con el que se le envia la entrada
(getparam, formparam, header o cookie). Es mas fiable que inferir el vector
leyendo las anotaciones del servlet, porque es el dato que usa la propia
herramienta de evaluacion del proyecto.

Identificacion del parametro inyectable, en este orden:
  1. El hijo cuyo `name` coincide con el nombre del caso (2259 casos).
  2. El hijo cuyo `value` coincide con el nombre del caso: entonces el
     parametro es su `name`, como en `someSecret: BenchmarkTest00009` (394).
  3. El ultimo hijo declarado, que es donde el crawler coloca el parametro
     inyectable cuando no aparece el nombre del caso, como en `Referer` (87).

Un hallazgo en un fichero que no es un caso de prueba (por ejemplo los helpers
del Benchmark) no tiene ruta HTTP asociada: se marca y la etapa de verificacion
lo dejara como "no verificable", sin descartarlo.

Limite de validez externa, importante al interpretar los resultados: esta etapa
es la unica del pipeline que **no es trasladable tal cual a una aplicacion
real**. Depende de dos cosas propias del banco de pruebas:

  1. `benchmark-crawler-http.xml`, que da la URL y el vector de cada caso ya
     resueltos. Una aplicacion cualquiera no publica ese mapa.
  2. La identificacion del caso por el nombre del fichero (BenchmarkTestNNNNN),
     que es una convencion del Benchmark.

El mecanismo de confirmacion cruzada de las etapas 6 y 7 si es independiente del
lenguaje, porque solo necesita una ruta HTTP y un parametro. Lo que no es
agnostico es *como se obtiene esa correspondencia*: fuera del Benchmark habria
que derivarla del enrutado del framework, de la instrumentacion de la aplicacion
o de un rastreo con cobertura, y ninguna de esas vias se ha evaluado aqui.
"""

from __future__ import annotations

import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..common import provenance
from ..common.config import repo_root
from ..normalize.normalize import SALIDA as ENTRADA, SCHEMA

SALIDA = "results/hallazgos_mapeados.csv"
SCHEMA_MAPEADO = SCHEMA + ["estado_mapeo"]


def carga_mapa(cfg: dict[str, Any]) -> tuple[dict[str, dict[str, str]], dict[str, int]]:
    """Construye el mapa caso -> {ruta_http, vector, parametro}."""
    ruta = repo_root() / cfg["benchmark"]["crawler_file"]
    raiz = ET.parse(ruta).getroot()

    mapa: dict[str, dict[str, str]] = {}
    criterios = {"por_nombre": 0, "por_valor": 0, "por_descarte": 0}

    for test in raiz.findall("benchmarkTest"):
        caso = test.get("tcName", "")
        hijos = list(test)
        if not caso or not hijos:
            continue

        elegido = next((c for c in hijos if c.get("name") == caso), None)
        if elegido is not None:
            criterios["por_nombre"] += 1
        else:
            elegido = next((c for c in hijos if c.get("value") == caso), None)
            if elegido is not None:
                criterios["por_valor"] += 1
            else:
                elegido = hijos[-1]
                criterios["por_descarte"] += 1

        mapa[caso] = {
            "ruta_http": urlparse(test.get("URL", "")).path,
            "vector": elegido.tag,
            "parametro": elegido.get("name", ""),
        }

    return mapa, criterios


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("5-map") as ctx:
        mapa, criterios = carga_mapa(cfg)

        origen = repo_root() / ENTRADA
        if not origen.exists():
            raise RuntimeError(f"No existe {ENTRADA}: ejecuta antes la etapa normalize.")

        with open(origen, "r", encoding="utf-8", newline="") as fh:
            filas = list(csv.DictReader(fh))

        mapeados = sin_ruta = 0
        for fila in filas:
            datos = mapa.get(fila.get("caso", ""))
            if datos is None:
                fila["estado_mapeo"] = "sin_ruta"
                sin_ruta += 1
                continue

            fila["estado_mapeo"] = "mapeado"
            mapeados += 1
            fila["vector"] = datos["vector"]
            # Las alertas de ZAP ya traen ruta y parametro observados: no se
            # sobreescriben, solo se completa el vector que ZAP no informa.
            if fila["herramienta"] != "zap":
                fila["ruta_http"] = datos["ruta_http"]
                fila["parametro"] = datos["parametro"]

        destino = repo_root() / SALIDA
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=SCHEMA_MAPEADO)
            escritor.writeheader()
            for fila in filas:
                escritor.writerow({c: fila.get(c, "") for c in SCHEMA_MAPEADO})

        ctx["detail"] = f"{mapeados} mapeados, {sin_ruta} sin ruta HTTP; criterios={criterios}"
        provenance.record_event("mapeo_sast_http", {"criterios": criterios, "casos": len(mapa)})

    print(f"Mapeo completado -> {SALIDA}")
    print(f"  casos en el mapa del Benchmark: {len(mapa)}")
    print(f"  hallazgos con ruta HTTP: {mapeados}")
    print(f"  hallazgos sin ruta HTTP (no verificables): {sin_ruta}")
    print(f"  criterio de parametro: {criterios}")
