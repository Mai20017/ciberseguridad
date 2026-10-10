"""Etapa 6: confirmacion cruzada de cada hallazgo SAST con ZAP.

Por cada par (ruta HTTP, CWE) con hallazgos SAST se lanza un escaneo activo de
ZAP sobre esa URL concreta, con una politica que contiene unicamente las reglas
de ese CWE: asi una alerta de otra familia no puede confirmar el hallazgo.

Los ataques los genera integramente ZAP. Esta etapa no construye payloads: se
limita a lanzar el escaneo dirigido y a recoger, por cada par:

  - si ZAP levanto una alerta de ese CWE sobre esa URL;
  - los rasgos de todas las respuestas HTTP que ZAP provoco, que la etapa 7
    agrupa.

Tres clases de respuesta por ruta
---------------------------------
Siguiendo a Akrout et al. (2014), de cada ruta se capturan tres clases de
respuesta, no una:

  linea_base  respuesta a la entrada valida del crawler del Benchmark
  ref_rr      respuestas a valores aleatorios alfanumericos        (Sr)
  ref_rii     respuestas a valores malformados                     (Sii)
  prueba_zap  respuestas al ataque que genera ZAP                  (Svi)

El metodo original confirma una inyeccion cuando su respuesta «no es similar a
ninguna de las respuestas de Sii y Sr», es decir, comparando contra el
comportamiento de la ruta *al rechazar*, no contra su comportamiento normal.
Las dos referencias se capturan a la vez para que la etapa 7 pueda emitir los
dos veredictos sobre el mismo trafico y la comparacion entre metodos no quede
contaminada por la variabilidad del escaneo entre ejecuciones.

Interpretacion declarada: Rr y Rii se generan algoritmicamente (cadenas
aleatorias, el segundo sobre un alfabeto con metacaracteres y delimitadores sin
cerrar). No son una tabla de payloads escrita a mano, y los ataques siguen
siendo los de ZAP; Akrout genera las suyas «a partir de una gramatica».

Estados de confirmacion:
  - confirmado:     ZAP levanto una alerta de ese CWE en esa URL.
  - no_confirmado:  ZAP pudo probarlo y no levanto ninguna.
  - no_verificable: no hay ruta HTTP, o ZAP 2.15 no tiene regla para ese CWE.
                    Nunca se descarta: hacerlo atribuiria al hallazgo una
                    limitacion del motor dinamico.
  - observado_dast: hallazgo propio de ZAP, que ya es una observacion dinamica.
"""

from __future__ import annotations

import csv
import difflib
import random
import string
import time
import urllib.parse
from typing import Any

import requests

from ..common import provenance
from ..common.config import repo_root
from ..dast.run_zap import configure, reset_session, run_crawler, zap_client
from ..mapping.sast_to_http import SALIDA as ENTRADA, SCHEMA_MAPEADO

SALIDA = "results/hallazgos_verificados.csv"
SALIDA_RESPUESTAS = "results/respuestas_zap.csv"
SCHEMA_VERIFICADO = SCHEMA_MAPEADO + [
    "estado_confirmacion",
    "evidencia_zap",
    "n_peticiones_zap",
]
SCHEMA_RESPUESTAS = [
    "ruta_http", "cwe", "tipo", "msg_id", "status", "longitud",
    "similitud", "similitud_rechazo",
]


def _politica(cwe: int) -> str:
    return f"tft-cwe-{cwe}"


def crea_politicas(cfg: dict[str, Any]) -> dict[int, str]:
    """Crea una politica de escaneo por CWE con solo las reglas de ese CWE."""
    zap = zap_client(cfg)
    existentes = zap.view("ascan", "scanPolicyNames")["scanPolicyNames"]
    politicas: dict[int, str] = {}

    for cwe, reglas in cfg["zap_rules_by_cwe"].items():
        nombre = _politica(cwe)
        if nombre not in existentes:
            zap.action("ascan", "addScanPolicy", scanPolicyName=nombre)
        zap.action("ascan", "disableAllScanners", scanPolicyName=nombre)
        zap.action(
            "ascan", "enableScanners",
            ids=",".join(str(r) for r in reglas), scanPolicyName=nombre,
        )
        politicas[int(cwe)] = nombre

    print(f"Politicas dirigidas creadas: {sorted(politicas.values())}")
    return politicas


def _url_de(mensaje: dict[str, Any]) -> str:
    cabecera = (mensaje.get("requestHeader") or "").splitlines()
    if not cabecera:
        return ""
    partes = cabecera[0].split()
    return partes[1] if len(partes) > 1 else ""


def _metodo_de(mensaje: dict[str, Any]) -> str:
    cabecera = (mensaje.get("requestHeader") or "").splitlines()
    return cabecera[0].split(" ", 1)[0] if cabecera else "GET"


def _status_de(mensaje: dict[str, Any]) -> int:
    cabecera = (mensaje.get("responseHeader") or "").splitlines()
    if not cabecera:
        return 0
    partes = cabecera[0].split()
    try:
        return int(partes[1]) if len(partes) > 1 else 0
    except ValueError:
        return 0


def mensajes_desde(cfg: dict[str, Any], inicio: int, limite: int) -> list[dict[str, Any]]:
    """Lee los mensajes del historial de ZAP a partir de un indice.

    Se usa el indice en lugar del filtro por URL porque ese filtro obliga a ZAP
    a recorrer todo el historial y se vuelve inviable cuando este crece.
    """
    zap = zap_client(cfg)
    salida: list[dict[str, Any]] = []
    paso = 100
    while len(salida) < limite:
        pedir = min(paso, limite - len(salida))
        lote = zap.view("core", "messages", start=inicio + len(salida), count=pedir)["messages"]
        if not lote:
            break
        salida.extend(lote)
        if len(lote) < pedir:
            break
    return salida


def linea_base_por_ruta(cfg: dict[str, Any], total_crawl: int) -> dict[str, dict[str, Any]]:
    """Captura la respuesta del crawler (entrada inocua) para cada ruta."""
    limite = cfg["clustering"]["max_body_chars"]
    base: dict[str, dict[str, Any]] = {}
    for mensaje in mensajes_desde(cfg, 0, total_crawl):
        # Se indexa por la URL sin query string, porque la etapa 6 busca la
        # linea base por ruta; indexar con ella dejaba sin linea base a todos
        # los casos getparam. La URL completa se conserva aparte, porque es la
        # que ascan necesita para localizar el nodo (ver "url_completa").
        completa = _url_de(mensaje)
        url = completa.split("?")[0]
        if not url or url in base:
            continue
        cuerpo = (mensaje.get("responseBody") or "")[:limite]
        base[url] = {
            "msg_id": mensaje.get("id", ""),
            "status": _status_de(mensaje),
            "cuerpo": cuerpo,
            "longitud": len(cuerpo),
            # Peticion exacta del rastreo. Hace falta completa (cabeceras y
            # cuerpo) para poder reenviarla cambiando solo el valor del
            # parametro inyectable y construir asi las clases Rr y Rii.
            "peticion_cabecera": mensaje.get("requestHeader") or "",
            "peticion_cuerpo": mensaje.get("requestBody") or "",
            # URL tal cual la pidio el crawler, con su query string. En los
            # casos getparam el nodo del arbol de ZAP es la URL *con* query, de
            # modo que ascan rechaza con 400 la URL limpia. Hay que darle esta.
            "url_completa": completa,
            # El crawler usa POST en 2200 de los 2740 casos y GET en el resto.
            # ascan localiza el nodo del arbol por URL *y* metodo, asi que hay
            # que repetir el metodo y el cuerpo exactos que uso el crawler.
            "metodo": _metodo_de(mensaje),
            "cuerpo_peticion": mensaje.get("requestBody") or "",
        }
    return base


def _similitud(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio() if a else 0.0


def _rasgos(
    mensaje: dict[str, Any], referencia: str, limite: int, ancla_rechazo: str = ""
) -> dict[str, Any]:
    """Rasgos de una respuesta HTTP.

    `similitud` mide el parecido con la respuesta a la entrada valida, y
    `similitud_rechazo` el parecido con una respuesta de rechazo de la misma
    ruta (la primera de la clase Rr). Hacen falta las dos: con una sola, una
    respuesta de rechazo y una respuesta al ataque que se alejen lo mismo de la
    entrada valida caen en el mismo punto del espacio de rasgos y el
    agrupamiento no puede distinguirlas, que es precisamente lo que la regla de
    Akrout necesita decidir.
    """
    cuerpo = (mensaje.get("responseBody") or "")[:limite]
    return {
        "msg_id": mensaje.get("id", ""),
        "status": _status_de(mensaje),
        "longitud": len(cuerpo),
        "similitud": round(_similitud(referencia, cuerpo), 4),
        "similitud_rechazo": round(_similitud(ancla_rechazo, cuerpo), 4),
    }


# --- Linea base de referencia de Akrout et al. (2014) ---------------------
#
# El metodo original compara la respuesta al ataque con dos clases de
# peticiones que fallan a proposito, no con la respuesta normal:
#
#   Rr  "peticiones generadas con palabras elegidas al azar de [a-zA-Z0-9]+"
#   Rii inyecciones sintacticamente invalidas
#
# y la regla es: una peticion Rvi (ataque) cuya respuesta no se parece a
# ninguna de Sr ni Sii se considera una inyeccion valida.
#
# Interpretacion aplicada aqui, que conviene declarar en la memoria: Rr se
# genera con cadenas aleatorias alfanumericas, y Rii con cadenas aleatorias
# sobre un alfabeto que incluye metacaracteres y delimitadores sin cerrar. Son
# valores *generados*, no una tabla de payloads escrita a mano; los ataques
# (Rvi) los sigue generando ZAP. Akrout genera las suyas "a partir de una
# gramatica", que es el mismo principio.

ALFABETO_RR = string.ascii_letters + string.digits
# Metacaracteres que rompen la sintaxis de SQL, XML/XPath, HTML y shell. No
# forman payloads: se combinan al azar, de modo que la peticion resultante es
# sintacticamente invalida y la aplicacion la rechaza.
METACARACTERES = "'\"`;()<>[]{}|&$\\/*%#"


def _valor_rr(aleatorio: random.Random) -> str:
    n = aleatorio.randint(6, 16)
    return "".join(aleatorio.choice(ALFABETO_RR) for _ in range(n))


def _valor_rii(aleatorio: random.Random) -> str:
    """Cadena aleatoria con metacaracteres y delimitadores deliberadamente sin cerrar."""
    n = aleatorio.randint(6, 16)
    bruto = [
        aleatorio.choice(METACARACTERES if aleatorio.random() < 0.45 else ALFABETO_RR)
        for _ in range(n)
    ]
    # Garantiza al menos un delimitador sin cerrar al principio
    return aleatorio.choice("'\"(") + "".join(bruto)


def _sustituye_parametro(
    cabecera: str, cuerpo: str, parametro: str, vector: str, valor: str
) -> tuple[str, str]:
    """Reemplaza el valor del parametro inyectable en la peticion del rastreo.

    Devuelve (cabecera, cuerpo) listos para reenviar. El sitio donde vive el
    parametro depende del vector, que la etapa 5 ya determino a partir del mapa
    del Benchmark.
    """
    # La cabecera que devuelve ZAP termina con la linea en blanco que separa
    # cabeceras de cuerpo. Hay que quitarla: si no, al anadir Content-Length
    # este queda DESPUES del separador, es decir dentro del cuerpo, y la
    # peticion resultante esta mal formada (el valor inyectado no llega a la
    # aplicacion y el servidor puede responder 400 por el motivo equivocado).
    lineas = cabecera.replace("\r\n", "\n").split("\n")
    while lineas and not lineas[-1].strip():
        lineas.pop()
    if not lineas or not parametro:
        return cabecera, cuerpo
    codificado = urllib.parse.quote(valor, safe="")

    def reescribe_consulta(url: str) -> str:
        partes = urllib.parse.urlsplit(url)
        pares = urllib.parse.parse_qsl(partes.query, keep_blank_values=True)
        if not any(k == parametro for k, _ in pares):
            return url
        nuevos = [(k, valor if k == parametro else v) for k, v in pares]
        return urllib.parse.urlunsplit(
            (partes.scheme, partes.netloc, partes.path,
             urllib.parse.urlencode(nuevos), partes.fragment)
        )

    if vector == "getparam":
        trozos = lineas[0].split(" ")
        if len(trozos) >= 2:
            trozos[1] = reescribe_consulta(trozos[1])
            lineas[0] = " ".join(trozos)
    elif vector == "formparam":
        pares = urllib.parse.parse_qsl(cuerpo, keep_blank_values=True)
        if any(k == parametro for k, _ in pares):
            cuerpo = urllib.parse.urlencode(
                [(k, valor if k == parametro else v) for k, v in pares]
            )
    elif vector == "header":
        for i, linea in enumerate(lineas[1:], start=1):
            if linea.lower().startswith(parametro.lower() + ":"):
                lineas[i] = f"{parametro}: {valor}"
                break
    elif vector == "cookie":
        for i, linea in enumerate(lineas[1:], start=1):
            if linea.lower().startswith("cookie:"):
                galletas = [c.strip() for c in linea.split(":", 1)[1].split(";") if c.strip()]
                salida = []
                for c in galletas:
                    nombre = c.split("=", 1)[0].strip()
                    salida.append(f"{nombre}={codificado}" if nombre == parametro else c)
                lineas[i] = "Cookie: " + "; ".join(salida)
                break

    # Content-Length debe corresponder al cuerpo que se envia, o ZAP rechaza
    # la peticion o el servidor lee un cuerpo truncado.
    lineas = [l for l in lineas if not l.lower().startswith("content-length:")]
    if cuerpo:
        lineas.append(f"Content-Length: {len(cuerpo.encode('utf-8'))}")
    return "\r\n".join(lineas), cuerpo


def referencias_de_rechazo(
    cfg: dict[str, Any],
    lb: dict[str, Any],
    parametro: str,
    vector: str,
    referencia: str,
    aleatorio: random.Random,
) -> tuple[list[dict[str, Any]], str]:
    """Envia las clases Rr y Rii a traves de ZAP.

    Devuelve (rasgos de Sr union Sii, cuerpo de la primera respuesta de rechazo).
    Ese cuerpo es el ancla contra la que se mide `similitud_rechazo` del resto
    de respuestas, incluidas las que provoque despues el escaneo activo.
    """
    cl = cfg["clustering"]
    plan = [("ref_rr", int(cl.get("referencias_rr", 0)), _valor_rr),
            ("ref_rii", int(cl.get("referencias_rii", 0)), _valor_rii)]
    cabecera_base = lb.get("peticion_cabecera") or ""
    cuerpo_base = lb.get("peticion_cuerpo") or ""
    if not cabecera_base or not parametro:
        return [], ""

    zap = zap_client(cfg)
    limite = cl["max_body_chars"]
    salida: list[dict[str, Any]] = []
    ancla = ""
    for tipo, cuantas, generador in plan:
        for _ in range(cuantas):
            cabecera, cuerpo = _sustituye_parametro(
                cabecera_base, cuerpo_base, parametro, vector, generador(aleatorio)
            )
            cruda = cabecera + "\r\n\r\n" + cuerpo
            try:
                respuesta = zap.action("core", "sendRequest", request=cruda, followRedirects="false")
            except requests.HTTPError:
                continue
            for mensaje in respuesta.get("sendRequest", []):
                if not ancla:
                    ancla = (mensaje.get("responseBody") or "")[:limite]
                salida.append({"tipo": tipo, **_rasgos(mensaje, referencia, limite, ancla)})
    return salida, ancla


def alertas_desde(cfg: dict[str, Any], inicio: int, limite: int = 500) -> list[dict[str, Any]]:
    """Lee las alertas por indice, no por URL.

    El filtro por baseurl obliga a ZAP a recorrer toda la lista de alertas y se
    degrada a medida que la sesion crece; con miles de escaneos dirigidos eso
    domina el tiempo de la etapa.
    """
    zap = zap_client(cfg)
    salida: list[dict[str, Any]] = []
    paso = 100
    while len(salida) < limite:
        pedir = min(paso, limite - len(salida))
        lote = zap.view("alert", "alerts", start=inicio + len(salida), count=pedir)["alerts"]
        if not lote:
            break
        salida.extend(lote)
        if len(lote) < pedir:
            break
    return salida


def total_mensajes(cfg: dict[str, Any]) -> int:
    return int(zap_client(cfg).view("core", "numberOfMessages")["numberOfMessages"])


def total_alertas(cfg: dict[str, Any]) -> int:
    return int(zap_client(cfg).view("core", "numberOfAlerts")["numberOfAlerts"])


def alertas_pasivas_por_url(cfg: dict[str, Any], total: int) -> dict[str, set[str]]:
    """Mapa url -> CWE de las alertas que las reglas pasivas generaron al rastrear.

    Es lo que permite verificar los CWE pasivos (cookie sin atributo Secure),
    para los que no hay regla de escaneo activo.
    """
    mapa: dict[str, set[str]] = {}
    for alerta in alertas_desde(cfg, 0, total):
        url = (alerta.get("url") or "").split("?")[0]
        if url:
            mapa.setdefault(url, set()).add(str(alerta.get("cweid", "")))
    return mapa


def _espera_escaneo(cfg: dict[str, Any], scan_id: str, timeout: int = 300) -> None:
    zap = zap_client(cfg)
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if int(zap.view("ascan", "status", scanId=scan_id)["status"]) >= 100:
            return
        time.sleep(1)
    zap.action("ascan", "stop", scanId=scan_id)


def prepara_sesion(cfg: dict[str, Any]) -> dict[str, Any]:
    """Arranca una sesion limpia de ZAP y captura su estado inicial."""
    reset_session(cfg)
    configure(cfg)
    run_crawler(cfg)
    # El arbol de ZAP incluye nodos padre sin peticion propia, asi que su
    # numero de URLs no sirve para saber cuantos mensajes genero el rastreo.
    mensajes_rastreo = total_mensajes(cfg)
    politicas = crea_politicas(cfg)
    lineas_base = linea_base_por_ruta(cfg, mensajes_rastreo)
    marca_alertas = total_alertas(cfg)
    pasivas = alertas_pasivas_por_url(cfg, marca_alertas)
    print(f"  lineas base {len(lineas_base)}; alertas pasivas {marca_alertas} en {len(pasivas)} URLs")
    return {
        "politicas": politicas,
        "lineas_base": lineas_base,
        "marca_alertas": marca_alertas,
        "pasivas": pasivas,
    }


def run_stage(cfg: dict[str, Any]) -> None:
    origen = repo_root() / ENTRADA
    if not origen.exists():
        raise RuntimeError(f"No existe {ENTRADA}: ejecuta antes las etapas normalize y map.")
    with open(origen, "r", encoding="utf-8", newline="") as fh:
        filas = list(csv.DictReader(fh))

    ambito = set(cfg["evaluation"]["benchmark_cwes"])
    raiz = cfg["benchmark"]["internal_base_url"].rstrip("/")
    base_url = raiz[: raiz.rfind("/benchmark")] if "/benchmark" in raiz else raiz
    limite_cuerpo = cfg["clustering"]["max_body_chars"]
    tope_mensajes = cfg["clustering"]["max_mensajes_por_par"]

    with provenance.stage("6-verify") as ctx:
        sesion = prepara_sesion(cfg)
        rotacion = cfg["clustering"]["max_pares_por_sesion"]

        pares: dict[tuple[str, int], str] = {}
        # Parametro y vector inyectable de cada par: los necesita la generacion
        # de las clases Rr y Rii, que tienen que tocar el mismo parametro que
        # ZAP va a atacar.
        objetivo: dict[tuple[str, int], tuple[str, str]] = {}
        for fila in filas:
            if fila["herramienta"] == "zap" or fila["estado_mapeo"] != "mapeado":
                continue
            try:
                cwe = int(fila["cwe"])
            except (TypeError, ValueError):
                continue
            if cwe in ambito:
                clave = (fila["ruta_http"], cwe)
                pares.setdefault(clave, "")
                objetivo.setdefault(clave, (fila.get("parametro", ""), fila.get("vector", "")))

        print(f"Pares (ruta, CWE) a verificar: {len(pares)}")
        zap = zap_client(cfg)
        respuestas: list[dict[str, Any]] = []
        evidencias: dict[tuple[str, int], str] = {}
        peticiones: dict[tuple[str, int], int] = {}
        cwes_pasivos = {str(c) for c in cfg["zap_passive_cwes"]}
        escaneados = 0
        t0 = time.monotonic()
        # Semilla fija: las clases Rr y Rii son aleatorias pero reproducibles,
        # de modo que repetir la etapa genera las mismas peticiones.
        aleatorio = random.Random(20261009)

        for i, (ruta, cwe) in enumerate(sorted(pares), start=1):
            url = base_url + ruta

            if str(cwe) in cwes_pasivos:
                # Lo detecta una regla pasiva al observar la respuesta del
                # rastreo: no hace falta escaneo activo.
                if str(cwe) in sesion["pasivas"].get(url, set()):
                    pares[(ruta, cwe)] = "confirmado"
                    evidencias[(ruta, cwe)] = "regla pasiva de ZAP sobre la respuesta del rastreo"
                else:
                    pares[(ruta, cwe)] = "no_confirmado"
                continue

            if cwe not in sesion["politicas"]:
                pares[(ruta, cwe)] = "no_verificable"
                evidencias[(ruta, cwe)] = "ZAP 2.15 no tiene regla activa para este CWE"
                continue

            if escaneados and escaneados % rotacion == 0:
                print(f"  rotando la sesion de ZAP tras {escaneados} escaneos", flush=True)
                sesion = prepara_sesion(cfg)

            lb = sesion["lineas_base"].get(url, {})
            referencia = lb.get("cuerpo", "")
            # Clases Rr y Rii de Akrout: se envian antes del ataque, para que
            # la linea base de rechazo exista cuando la etapa 7 agrupe y para
            # fijar el ancla de similitud_rechazo.
            parametro, vector = objetivo.get((ruta, cwe), ("", ""))
            refs, ancla = referencias_de_rechazo(
                cfg, lb, parametro, vector, referencia, aleatorio
            )

            if referencia:
                respuestas.append(
                    {
                        "ruta_http": ruta, "cwe": cwe, "tipo": "linea_base",
                        "msg_id": lb["msg_id"], "status": lb["status"],
                        "longitud": lb["longitud"], "similitud": 1.0,
                        "similitud_rechazo": round(_similitud(ancla, referencia), 4),
                    }
                )
            for rasgos in refs:
                respuestas.append({"ruta_http": ruta, "cwe": cwe, **rasgos})

            # ascan localiza el nodo del arbol por URL exacta: en los casos
            # getparam esa URL incluye la query string que uso el crawler, y sin
            # ella ZAP responde 400 (url_not_found). Pasarla limpia dejaba sin
            # escanear los 556 casos de entrada por parametro GET.
            parametros = {
                "url": lb.get("url_completa") or url,
                "recurse": "false",
                "inScopeOnly": "false",
                "scanPolicyName": sesion["politicas"][cwe],
                "method": lb.get("metodo", "GET"),
            }
            if lb.get("cuerpo_peticion"):
                parametros["postData"] = lb["cuerpo_peticion"]

            # La marca se pregunta a ZAP justo antes de escanear. Calcularla
            # sumando lo leido desincroniza la lectura en cuanto un escaneo
            # genera mas mensajes que el tope por par.
            marca_mensajes = total_mensajes(cfg)
            try:
                scan_id = zap.action("ascan", "scan", **parametros)["scan"]
            except requests.HTTPError:
                pares[(ruta, cwe)] = "no_verificable"
                evidencias[(ruta, cwe)] = "la ruta no esta en el arbol de ZAP"
                continue

            _espera_escaneo(cfg, scan_id)
            escaneados += 1
            # Peticiones que ZAP emitio para probar este par. Es la variable
            # dependiente "numero de peticiones HTTP": se mide como el avance
            # del contador de mensajes de ZAP durante el escaneo, no se estima.
            peticiones[(ruta, cwe)] = max(0, total_mensajes(cfg) - marca_mensajes)

            for mensaje in mensajes_desde(cfg, marca_mensajes, tope_mensajes):
                if _url_de(mensaje).split("?")[0] != url:
                    continue
                rasgos = _rasgos(mensaje, referencia, limite_cuerpo, ancla)
                respuestas.append({"ruta_http": ruta, "cwe": cwe, "tipo": "prueba_zap", **rasgos})

            nuevas = alertas_desde(cfg, sesion["marca_alertas"])
            sesion["marca_alertas"] += len(nuevas)
            confirmada = next(
                (
                    a for a in nuevas
                    if (a.get("url") or "").split("?")[0] == url and a.get("cweid") == str(cwe)
                ),
                None,
            )
            if confirmada:
                pares[(ruta, cwe)] = "confirmado"
                evidencias[(ruta, cwe)] = (
                    f"{confirmada.get('pluginId')}:{confirmada.get('name')} "
                    f"param={confirmada.get('param')}"
                )
            else:
                pares[(ruta, cwe)] = "no_confirmado"

            if i % 100 == 0 or i == len(pares):
                print(f"  verificados {i}/{len(pares)} ({int(time.monotonic() - t0)}s)", flush=True)

        resumen: dict[str, int] = {}
        for fila in filas:
            if fila["herramienta"] == "zap":
                estado, evidencia = "observado_dast", ""
            elif fila["estado_mapeo"] != "mapeado":
                estado, evidencia = "no_verificable", "sin ruta HTTP asociada"
            else:
                try:
                    cwe = int(fila["cwe"])
                except (TypeError, ValueError):
                    cwe = -1
                clave = (fila["ruta_http"], cwe)
                estado = pares.get(clave, "no_verificable")
                evidencia = evidencias.get(clave, "")
                if clave not in pares:
                    evidencia = "CWE fuera del ambito del Benchmark"
            fila["estado_confirmacion"] = estado
            fila["evidencia_zap"] = evidencia
            fila["n_peticiones_zap"] = peticiones.get(
                (fila.get("ruta_http", ""), int(fila["cwe"]) if fila["cwe"].isdigit() else -1), ""
            )
            resumen[estado] = resumen.get(estado, 0) + 1

        destino = repo_root() / SALIDA
        destino.parent.mkdir(parents=True, exist_ok=True)
        with open(destino, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=SCHEMA_VERIFICADO)
            escritor.writeheader()
            for fila in filas:
                escritor.writerow({c: fila.get(c, "") for c in SCHEMA_VERIFICADO})

        destino_resp = repo_root() / SALIDA_RESPUESTAS
        with open(destino_resp, "w", encoding="utf-8", newline="") as fh:
            escritor = csv.DictWriter(fh, fieldnames=SCHEMA_RESPUESTAS)
            escritor.writeheader()
            escritor.writerows(respuestas)

        total_peticiones = sum(peticiones.values())
        ctx["detail"] = (
            f"{len(pares)} pares verificados; {escaneados} escaneos activos; "
            f"{total_peticiones} peticiones HTTP; {len(respuestas)} respuestas de ZAP; {resumen}"
        )

    print(f"Confirmacion cruzada -> {SALIDA}")
    print(f"Respuestas HTTP de ZAP -> {SALIDA_RESPUESTAS} ({len(respuestas)} filas)")
    print(f"Escaneos activos dirigidos: {escaneados} de {len(pares)} pares")
    print(f"Peticiones HTTP emitidas por ZAP: {total_peticiones}")
    if peticiones:
        print(f"  media por par escaneado: {total_peticiones / len(peticiones):.1f}")
    for estado, n in sorted(resumen.items()):
        print(f"  {estado}: {n}")
