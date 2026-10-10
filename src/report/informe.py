"""Informe final unico y legible por una persona.

El pipeline produce una decena de CSV, que sirven para auditar el experimento
pero no para responder a la pregunta que hace quien lo ejecuta: "¿que ha salido y
donde lo leo?". Esta etapa reune todo en dos ficheros:

  - results/INFORME.html  ->  el informe para leer, de una sola pagina
  - results/lista_revision.csv  ->  la lista de trabajo accionable

No calcula ninguna metrica nueva: solo lee lo que las etapas anteriores ya
escribieron. Si falta algun fichero (porque esa etapa no se ha ejecutado), la
seccion correspondiente avisa de ello en lugar de inventar nada.
"""

from __future__ import annotations

import csv
import html
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..common import provenance
from ..common.config import repo_root

SALIDA_HTML = "results/INFORME.html"
SALIDA_LISTA = "results/lista_revision.csv"

# Nombre corriente de cada CWE, para que el informe no sea una lista de numeros.
NOMBRES_CWE = {
    22: "Path traversal (acceso a ficheros por ruta manipulada)",
    78: "Inyeccion de comandos del sistema operativo",
    79: "Cross-site scripting (XSS) reflejado",
    89: "Inyeccion SQL",
    90: "Inyeccion LDAP",
    327: "Uso de algoritmo criptografico debil o roto",
    328: "Uso de funcion de hash debil",
    330: "Uso de valores aleatorios no seguros",
    501: "Violacion de limite de confianza",
    614: "Cookie de sesion sin el atributo Secure",
    643: "Inyeccion XPath",
}

# Que significa cada veredicto, en lenguaje de operador.
SIGNIFICADO = {
    "confirmado": "El ataque de ZAP cambio el comportamiento de la aplicacion, "
                  "o ZAP levanto una alerta propia. Hay que revisarlo primero.",
    "descartado": "ZAP pudo atacar esa ruta y la aplicacion respondio igual que "
                  "ante una entrada normal. Probable falso positivo.",
    "no_verificable": "No se pudo comprobar dinamicamente: el hallazgo no tiene "
                      "ruta HTTP, o ZAP no tiene reglas para ese tipo de fallo. "
                      "Se conserva: no descartarlo es deliberado.",
    "observado_dast": "Lo encontro ZAP por si mismo durante el escaneo, no el "
                      "analisis estatico.",
}

COLUMNAS_LISTA = [
    "prioridad", "cwe", "tipo", "caso", "archivo", "linea",
    "ruta_http", "parametro", "vector", "herramienta", "severidad",
    "estado_final", "evidencia_zap",
]


def _lee_csv(ruta: Path) -> list[dict[str, str]]:
    if not ruta.exists():
        return []
    with open(ruta, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _nombre(cwe: Any) -> str:
    try:
        return NOMBRES_CWE.get(int(cwe), f"CWE-{cwe}")
    except (TypeError, ValueError):
        return str(cwe)


def lista_accionable(hallazgos: list[dict[str, str]]) -> list[dict[str, str]]:
    """Construye la lista de trabajo: lo confirmado primero, luego lo no verificable.

    Se deduplica por (archivo, linea, CWE) para los hallazgos estaticos y por
    (ruta, parametro, CWE) para los de ZAP: dos avisos sobre el mismo sitio y el
    mismo tipo de fallo son un unico item de revision.
    """
    orden = {"confirmado": 1, "no_verificable": 2, "observado_dast": 3}
    vistos: set[tuple[str, ...]] = set()
    salida: list[dict[str, str]] = []

    for fila in sorted(
        (f for f in hallazgos if f.get("estado_final") in orden),
        key=lambda f: (orden[f["estado_final"]], str(f.get("cwe", "")), f.get("archivo", "")),
    ):
        if fila.get("herramienta") == "zap":
            clave = ("zap", fila.get("ruta_http", ""), fila.get("parametro", ""), fila.get("cwe", ""))
        else:
            clave = ("sast", fila.get("archivo", ""), fila.get("linea", ""), fila.get("cwe", ""))
        if clave in vistos:
            continue
        vistos.add(clave)
        salida.append(
            {
                "prioridad": orden[fila["estado_final"]],
                "cwe": fila.get("cwe", ""),
                "tipo": _nombre(fila.get("cwe", "")),
                "caso": fila.get("caso", ""),
                "archivo": fila.get("archivo", ""),
                "linea": fila.get("linea", ""),
                "ruta_http": fila.get("ruta_http", ""),
                "parametro": fila.get("parametro", ""),
                "vector": fila.get("vector", ""),
                "herramienta": fila.get("herramienta", ""),
                "severidad": fila.get("severidad", ""),
                "estado_final": fila.get("estado_final", ""),
                "evidencia_zap": (fila.get("evidencia_zap") or "")[:300],
            }
        )
    return salida


ESTILO = """
:root {
  --fondo: #fcfcfb; --tinta: #0b0b0b; --tinta2: #52514e;
  --linea: #dedcd5; --acento: #2a78d6; --alerta: #eb6834; --ok: #1baf7a;
  --caja: #ffffff;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --fondo: #16160f; --tinta: #f5f4ee; --tinta2: #a8a69c;
    --linea: #343128; --caja: #1e1e16;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 0 16px 64px; background: var(--fondo); color: var(--tinta);
  font: 16px/1.6 -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 900px; margin: 0 auto; }
h1 { font-size: 1.7rem; margin: 2rem 0 .3rem; }
h2 { font-size: 1.2rem; margin: 2.6rem 0 .6rem; padding-bottom: .3rem;
  border-bottom: 1px solid var(--linea); }
h3 { font-size: 1rem; margin: 1.6rem 0 .4rem; }
p, li { color: var(--tinta2); }
.sub { color: var(--tinta2); font-size: .9rem; margin: 0 0 1.5rem; }
table { width: 100%; border-collapse: collapse; margin: .8rem 0 1.4rem; font-size: .88rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--linea); }
th { color: var(--tinta); font-weight: 600; }
td { color: var(--tinta2); }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
.tarjetas { display: flex; flex-wrap: wrap; gap: 12px; margin: 1.2rem 0; }
.tarjeta { flex: 1 1 160px; background: var(--caja); border: 1px solid var(--linea);
  border-radius: 10px; padding: .9rem 1rem; }
.tarjeta .cifra { font-size: 1.8rem; font-weight: 650; color: var(--tinta);
  font-variant-numeric: tabular-nums; }
.tarjeta .et { font-size: .78rem; color: var(--tinta2); text-transform: uppercase;
  letter-spacing: .04em; }
.aviso { background: var(--caja); border-left: 3px solid var(--alerta);
  padding: .8rem 1rem; border-radius: 0 8px 8px 0; margin: 1rem 0; }
.aviso.ok { border-left-color: var(--ok); }
code { background: var(--caja); border: 1px solid var(--linea); border-radius: 4px;
  padding: .08em .35em; font-size: .88em; }
.falta { color: var(--alerta); font-style: italic; }
"""


def _tabla(cabeceras: list[str], filas: list[list[Any]], numericas: set[int] = frozenset()) -> str:
    th = "".join(
        f'<th class="n">{html.escape(str(c))}</th>' if i in numericas
        else f"<th>{html.escape(str(c))}</th>"
        for i, c in enumerate(cabeceras)
    )
    cuerpo = []
    for fila in filas:
        tds = "".join(
            f'<td class="n">{html.escape(str(v))}</td>' if i in numericas
            else f"<td>{html.escape(str(v))}</td>"
            for i, v in enumerate(fila)
        )
        cuerpo.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{th}</tr></thead><tbody>{''.join(cuerpo)}</tbody></table>"


def construye_html(cfg: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    raiz = repo_root()
    hallazgos = _lee_csv(raiz / "results/hallazgos.csv")
    metricas = _lee_csv(raiz / "results/metrics.csv")
    validacion = _lee_csv(raiz / "results/validacion_scorer_oficial_por_caso.csv")
    carga = _lee_csv(raiz / "results/carga_revision.csv")
    tiempos = _lee_csv(raiz / "results/stage_times.csv")

    lista = lista_accionable(hallazgos)
    estados = Counter(f.get("estado_final", "") for f in hallazgos)
    confirmados = [f for f in lista if f["estado_final"] == "confirmado"]
    no_verificables = [f for f in lista if f["estado_final"] == "no_verificable"]

    p: list[str] = []
    p.append(f"<h1>Informe de analisis de vulnerabilidades</h1>")
    p.append(
        f'<p class="sub">Aplicacion analizada: <strong>{html.escape(cfg["meta"]["project"])}</strong> '
        f'sobre OWASP Benchmark v{html.escape(str(cfg["meta"]["benchmark_version"]))}. '
        f'Generado el {datetime.now(timezone.utc):%d/%m/%Y a las %H:%M} UTC.</p>'
    )

    # --- 1. Resumen ---
    p.append("<h2>1. Que hay que revisar</h2>")
    p.append('<div class="tarjetas">')
    for et, cifra in (
        ("A revisar primero", len(confirmados)),
        ("Sin comprobar", len(no_verificables)),
        ("Items totales", len(lista)),
        ("Avisos brutos", len(hallazgos)),
    ):
        p.append(f'<div class="tarjeta"><div class="cifra">{cifra}</div><div class="et">{et}</div></div>')
    p.append("</div>")
    p.append(
        "<p>Las cifras de arriba son <em>items de revision</em>: varios avisos sobre la misma "
        "linea de codigo y el mismo tipo de fallo cuentan como uno, porque son el mismo trabajo. "
        f"La lista completa, ordenada por prioridad, esta en <code>{SALIDA_LISTA}</code>.</p>"
    )

    p.append("<h3>Que significa cada veredicto</h3>")
    p.append(
        _tabla(
            ["Veredicto", "Avisos", "Que quiere decir"],
            [[e, estados.get(e, 0), SIGNIFICADO.get(e, "")] for e in
             ("confirmado", "no_verificable", "observado_dast", "descartado")],
            numericas={1},
        )
    )

    # --- 2. Por tipo de vulnerabilidad ---
    p.append("<h2>2. Confirmado, por tipo de vulnerabilidad</h2>")
    if confirmados:
        por_cwe: dict[str, list[dict[str, str]]] = defaultdict(list)
        for f in confirmados:
            por_cwe[f["cwe"]].append(f)
        filas = sorted(
            ([_nombre(c), f"CWE-{c}", len(v)] for c, v in por_cwe.items()),
            key=lambda r: -r[2],
        )
        p.append(_tabla(["Tipo de vulnerabilidad", "CWE", "Items"], filas, numericas={2}))
        p.append("<h3>Primeros 20 items, como ejemplo del formato de la lista</h3>")
        ejemplo = [
            [f["cwe"], f["caso"], f["archivo"].split("/")[-1], f["linea"],
             f["ruta_http"], f["parametro"]]
            for f in confirmados[:20]
        ]
        p.append(_tabla(["CWE", "Caso", "Fichero", "Linea", "Ruta HTTP", "Parametro"], ejemplo))
    else:
        p.append('<p class="falta">No hay hallazgos confirmados: ejecuta las etapas 6 y 7.</p>')

    # --- 3. Fiabilidad ---
    p.append("<h2>3. Fiabilidad de este informe</h2>")
    p.append(
        "<p>Esta seccion existe porque un informe de vulnerabilidades sin una medida de su "
        "propio error no se puede usar para decidir. El Benchmark trae la solucion conocida de "
        "sus 2.740 casos, de modo que aqui si se puede medir cuanto acierta el filtro.</p>"
    )
    totales = [m for m in metricas if m.get("cwe") == "TOTAL"]
    if totales:
        filas = [
            [m["configuracion"], m["descripcion"][:48], m["TP"], m["FP"], m["FN"],
             m["precision"], m["recall"], m["f1"], m["benchmark_score"]]
            for m in totales
        ]
        p.append(
            _tabla(
                ["Config", "Que es", "Aciertos", "Falsos pos.", "No vistos",
                 "Precision", "Exhaustividad", "F1", "Punt. OWASP"],
                filas, numericas={2, 3, 4, 5, 6, 7, 8},
            )
        )
        p.append(
            "<p><strong>Precision</strong>: de lo que el informe senala, cuanto es real. "
            "<strong>Exhaustividad</strong>: de lo que existe, cuanto encuentra. "
            "<strong>Punt. OWASP</strong>: la puntuacion oficial del Benchmark, "
            "exhaustividad menos tasa de falsa alarma.</p>"
        )
    else:
        p.append('<p class="falta">Falta results/metrics.csv: ejecuta la etapa 8.</p>')

    if validacion:
        iguales = sum(1 for v in validacion if v.get("coinciden_exactamente") == "si")
        clase = "ok" if iguales == len(validacion) else ""
        p.append(
            f'<div class="aviso {clase}"><strong>Contraste con la herramienta oficial de OWASP.</strong> '
            f"Las cifras de los motores por separado se han comparado con BenchmarkUtils, "
            f"el programa de puntuacion del propio proyecto OWASP Benchmark: "
            f"{iguales} de {len(validacion)} motores coinciden caso por caso, "
            f"sobre los 2.740 casos. Detalle en "
            f"<code>results/validacion_scorer_oficial_por_caso.csv</code>.</div>"
        )

    if carga:
        p.append("<h3>Cuanto trabajo ahorra de verdad</h3>")
        p.append(
            "<p>La reduccion de falsos positivos se mide sobre los casos que el Benchmark "
            "puntua. El trabajo real del auditor se paga sobre <em>todos</em> los avisos del "
            "informe, incluidos los de tipos que el Benchmark no puntua. Las dos cifras no son "
            "la misma, y aqui estan las dos.</p>"
        )
        filas = [
            [c["configuracion"], c["hallazgos_entregados"], c["items_distintos"],
             c["items_agrupando_dast_por_regla"], c["reduccion_items_vs_C1_pct"],
             c["reduccion_items_agrupados_vs_C1_pct"]]
            for c in carga
        ]
        p.append(
            _tabla(
                ["Config", "Avisos entregados", "Items (cota alta)",
                 "Items (cota baja)", "Reduccion % (alta)", "Reduccion % (baja)"],
                filas, numericas={1, 2, 3, 4, 5},
            )
        )

    # --- 4. Donde esta cada cosa ---
    p.append("<h2>4. Donde esta cada fichero</h2>")
    ficheros = [
        (SALIDA_LISTA, "La lista de trabajo: que revisar y en que orden", True),
        ("results/INFORME.html", "Este informe", True),
        ("results/metrics.csv", "Metricas por configuracion y por CWE", True),
        ("results/hallazgos.csv", "Todos los avisos con su veredicto y evidencia", True),
        ("results/carga_revision.csv", "Carga de revision sobre el informe completo", False),
        ("results/validacion_scorer_oficial.csv", "Contraste con el scorer oficial de OWASP", False),
        ("results/sensibilidad_clustering.csv", "Sensibilidad de los parametros del filtro", False),
        ("results/figuras/", "Graficas en PNG", True),
        ("results/entorno.txt", "Fecha, hardware, versiones y tiempo por etapa", True),
        ("results/sast/", "Salida original de Semgrep y SpotBugs, sin tocar", True),
        ("results/dast/zap.json", "Salida original de ZAP, sin tocar", True),
        ("results/provenance.jsonl", "Registro crudo de la ejecucion", True),
    ]
    filas = []
    for ruta, para_que, _ in ficheros:
        existe = (raiz / ruta).exists()
        filas.append([ruta, para_que, "si" if existe else "no generado"])
    p.append(_tabla(["Fichero", "Para que sirve", "Existe"], filas))

    # --- 5. Como se produjo ---
    p.append("<h2>5. Como se ha producido este informe</h2>")
    ultimas: dict[str, dict[str, str]] = {}
    for t in tiempos:
        if t.get("status") == "ok":
            ultimas[t["stage"]] = t
    if ultimas:
        filas = [
            [k, f'{float(v["duration_s"]) / 60:.1f}', (v.get("detail") or "")[:90]]
            for k, v in sorted(ultimas.items())
        ]
        p.append(_tabla(["Etapa", "Minutos", "Resultado"], filas, numericas={1}))
    p.append(
        "<p>Reproducirlo entero: <code>docker compose run --rm orchestrator "
        "python run_all.py --all</code>. Todas las versiones de herramienta y el hardware "
        "estan en <code>results/entorno.txt</code>, tal como cada herramienta se identifico "
        "durante la ejecucion.</p>"
    )

    cuerpo = "\n".join(p)
    return (
        "<!doctype html>\n"
        '<html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Informe de vulnerabilidades</title>"
        f"<style>{ESTILO}</style></head><body><main>{cuerpo}</main></body></html>\n"
    ), lista


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("12-informe") as ctx:
        documento, lista = construye_html(cfg)

        destino = repo_root() / SALIDA_HTML
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(documento, encoding="utf-8")

        destino_lista = repo_root() / SALIDA_LISTA
        with open(destino_lista, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=COLUMNAS_LISTA)
            escritor.writeheader()
            escritor.writerows(lista)

        confirmados = sum(1 for f in lista if f["estado_final"] == "confirmado")
        print(f"Informe       -> {SALIDA_HTML}")
        print(f"Lista a revisar -> {SALIDA_LISTA} ({len(lista)} items)")
        print(f"  de los cuales confirmados (prioridad 1): {confirmados}")
        ctx["detail"] = f"{len(lista)} items en la lista; {confirmados} confirmados"
