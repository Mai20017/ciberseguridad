"""Etapa 3: analisis dinamico (DAST) con OWASP ZAP en modo daemon.

El flujo reproduce la metodologia del propio Benchmark:
  1. Se reescriben las URL del fichero de crawler al host interno de la red
     Docker (el original las fija a localhost:8443, y si ZAP registrase ese
     host atacaria a su propio contenedor en lugar de al Benchmark).
  2. El crawler oficial del Benchmark (BenchmarkUtils) recorre los 2740 casos
     a traves del proxy de ZAP, poblando su arbol de sitios con la peticion
     exacta de cada caso, incluidos los vectores en cabecera y cookie.
  3. ZAP lanza un escaneo activo sobre ese arbol.
  4. Las alertas se exportan a JSON.

Detalle critico: por defecto ZAP solo inyecta en query string y datos POST
(TargetParamsInjectable=3). El Benchmark envia 657 casos por cabecera y 216 por
cookie, que quedarian fuera del escaneo. Esta etapa habilita los cinco vectores.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from ..common import provenance
from ..common.config import repo_root
from ..common.shell import run

# Bits de ScannerParam.TARGET_* de ZAP
INJECT_QUERYSTRING = 1
INJECT_POSTDATA = 2
INJECT_COOKIE = 4
INJECT_HTTPHEADERS = 8
INJECT_URLPATH = 16

# Politicas predefinidas de ZAP, con el formato St-<fuerza>-Th-<umbral>
_STRENGTH = {"LOW": "Low", "MEDIUM": "Med", "HIGH": "High", "INSANE": "Ins"}
_THRESHOLD = {"LOW": "Low", "MEDIUM": "Med", "HIGH": "High"}


class Zap:
    """Cliente minimo de la API JSON de ZAP."""

    def __init__(self, host: str, port: int, api_key: str) -> None:
        self.base = f"http://{host}:{port}"
        self.api_key = api_key

    # Los nombres de los argumentos llevan guion bajo para no colisionar con los
    # parametros de la propia API de ZAP (por ejemplo newSession recibe "name").
    def call(self, _component: str, _kind: str, _endpoint: str, **params: Any) -> dict[str, Any]:
        url = f"{self.base}/JSON/{_component}/{_kind}/{_endpoint}/"
        params["apikey"] = self.api_key
        # Timeout generoso: reiniciar una sesion con cientos de miles de
        # mensajes puede tardar varios minutos en responder.
        resp = requests.get(url, params=params, timeout=900)
        resp.raise_for_status()
        return resp.json()

    def view(self, _component: str, _endpoint: str, **params: Any) -> dict[str, Any]:
        return self.call(_component, "view", _endpoint, **params)

    def action(self, _component: str, _endpoint: str, **params: Any) -> dict[str, Any]:
        return self.call(_component, "action", _endpoint, **params)


def zap_client(cfg: dict[str, Any]) -> Zap:
    z = cfg["dast"]["zap"]
    return Zap("zap", z["api_port"], z["api_key"])


def policy_name(cfg: dict[str, Any]) -> str:
    z = cfg["dast"]["zap"]
    return f"St-{_STRENGTH[z['attack_strength']]}-Th-{_THRESHOLD[z['alert_threshold']]}"


def wait_for_api(cfg: dict[str, Any], timeout: int = 180) -> str:
    zap = zap_client(cfg)
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            return zap.view("core", "version")["version"]
        except requests.RequestException:
            time.sleep(3)
    raise RuntimeError(f"La API de ZAP no respondio en {timeout}s")


def configure(cfg: dict[str, Any]) -> None:
    """Habilita los vectores de inyeccion y fija los parametros del escaneo."""
    zap = zap_client(cfg)
    z = cfg["dast"]["zap"]

    injectable = INJECT_QUERYSTRING | INJECT_POSTDATA | INJECT_URLPATH
    if z["inject_cookies"]:
        injectable |= INJECT_COOKIE
    if z["inject_headers"]:
        injectable |= INJECT_HTTPHEADERS

    zap.action("ascan", "setOptionTargetParamsInjectable", Integer=injectable)
    zap.action(
        "ascan", "setOptionScanHeadersAllRequests",
        Boolean=str(bool(z["inject_headers"])).lower(),
    )
    zap.action("ascan", "setOptionThreadPerHost", Integer=z["threads_per_host"])
    zap.action("ascan", "setOptionMaxScanDurationInMins", Integer=z["max_scan_duration_min"])
    zap.action("ascan", "setOptionMaxRuleDurationInMins", Integer=z["max_rule_duration_min"])

    aplicado = int(zap.view("ascan", "optionTargetParamsInjectable")["TargetParamsInjectable"])
    if aplicado != injectable:
        raise RuntimeError(
            f"ZAP no acepto la configuracion de vectores: pedido {injectable}, aplicado {aplicado}"
        )

    print(f"ZAP configurado: vectores={injectable}, politica={policy_name(cfg)}")
    provenance.record_event(
        "zap_config",
        {
            "target_params_injectable": injectable,
            "scan_headers_all_requests": bool(z["inject_headers"]),
            "scan_policy": policy_name(cfg),
            "threads_per_host": z["threads_per_host"],
        },
    )


def reset_session(cfg: dict[str, Any]) -> None:
    """Arranca una sesion limpia de ZAP.

    Imprescindible para la integridad de los resultados: ZAP acumula las
    alertas de todos los escaneos de la sesion, incluidas las de pruebas
    piloto, y se mezclarian con las de la ejecucion oficial.
    """
    zap_client(cfg).action("core", "newSession", name="tft", overwrite="true")
    print("Sesion de ZAP reiniciada")


def record_scan_rules(cfg: dict[str, Any]) -> None:
    """Registra la version de los add-ons de reglas y el numero de reglas activas."""
    zap = zap_client(cfg)
    addons = zap.view("autoupdate", "installedAddons")["installedAddons"]
    reglas = {
        a["id"]: a.get("version")
        for a in addons
        if "ascanrules" in a.get("id", "") or "pscanrules" in a.get("id", "")
    }
    activas = zap.view("ascan", "scanners", scanPolicyName=policy_name(cfg))["scanners"]
    for addon, version in sorted(reglas.items()):
        provenance.record_tool_version(f"ZAP {addon}", str(version), source="add-on de ZAP")
    provenance.record_event(
        "zap_scan_rules",
        {"addons": reglas, "reglas_activas": len(activas)},
    )
    print(f"Reglas de ZAP: {len(activas)} activas; add-ons {reglas}")


def prepare_crawler_file(cfg: dict[str, Any]) -> Path:
    """Reescribe las URL del fichero de crawler al host interno de Docker."""
    bench = cfg["benchmark"]
    src = repo_root() / bench["crawler_file"]
    dst = repo_root() / bench["crawler_file_internal"]
    dst.parent.mkdir(parents=True, exist_ok=True)

    original = src.read_text(encoding="utf-8")
    host_url = bench["host_base_url"].rstrip("/") + "/"
    internal_url = bench["internal_base_url"].rstrip("/") + "/"
    reescritas = original.count(host_url)
    if reescritas == 0:
        raise RuntimeError(f"No se encontro ninguna URL {host_url} en {src}")
    dst.write_text(original.replace(host_url, internal_url), encoding="utf-8")
    print(f"Fichero de crawler preparado: {reescritas} URLs reescritas a {internal_url}")
    return dst


def run_crawler(cfg: dict[str, Any]) -> int:
    """Recorre los casos de prueba a traves del proxy de ZAP."""
    z = cfg["dast"]["zap"]
    nombre = Path(cfg["benchmark"]["crawler_file_internal"]).name
    cmd = [
        "docker", "compose", "run", "--rm",
        "-e", f"ZAP_API_KEY={z['api_key']}",
        "-e", f"CRAWLER_FILE=/out/{nombre}",
        "crawler", "/usr/local/bin/crawl.sh",
    ]
    with provenance.stage("3b-dast-crawl") as ctx:
        run(cmd, "dast-crawl", timeout=3600, cwd=repo_root())
        urls = len(zap_client(cfg).view("core", "urls")["urls"])
        if urls == 0:
            raise RuntimeError(
                "El crawler no registro ninguna URL en ZAP. Revisa logs/dast-crawl.log."
            )
        ctx["detail"] = f"{urls} URLs registradas en el arbol de ZAP"

    print(f"Crawler completado: {urls} URLs en el arbol de ZAP")
    provenance.record_tool_version(
        "BenchmarkUtils (crawler)",
        z["crawler_plugin_version"],
        source=f"commit {cfg['benchmark']['benchmark_utils']['commit']}",
    )
    return urls


def active_scan(cfg: dict[str, Any], target: str | None = None) -> dict[str, Any]:
    """Lanza el escaneo activo y espera a que termine."""
    zap = zap_client(cfg)
    url = target or cfg["benchmark"]["internal_base_url"]
    scan_id = zap.action(
        "ascan", "scan",
        url=url, recurse="true", inScopeOnly="false",
        scanPolicyName=policy_name(cfg),
    )["scan"]
    print(f"Escaneo activo {scan_id} iniciado sobre {url}")

    t0 = time.monotonic()
    ultimo = -1
    while True:
        estado = int(zap.view("ascan", "status", scanId=scan_id)["status"])
        if estado != ultimo:
            print(f"  progreso {estado}% ({int(time.monotonic() - t0)}s)", flush=True)
            ultimo = estado
        if estado >= 100:
            break
        time.sleep(15)

    return {
        "scan_id": scan_id,
        "elapsed_s": round(time.monotonic() - t0, 1),
        "target": url,
    }


def export_alerts(cfg: dict[str, Any], baseurl: str | None = None) -> int:
    """Exporta todas las alertas de ZAP a JSON."""
    zap = zap_client(cfg)
    url = baseurl or cfg["benchmark"]["internal_base_url"]
    alertas: list[dict[str, Any]] = []
    bloque = 1000
    while True:
        lote = zap.view("alert", "alerts", baseurl=url, start=len(alertas), count=bloque)["alerts"]
        alertas.extend(lote)
        if len(lote) < bloque:
            break

    destino = repo_root() / cfg["dast"]["zap"]["output_json"]
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(destino, "w", encoding="utf-8") as fh:
        json.dump({"baseurl": url, "alerts": alertas}, fh, ensure_ascii=False, indent=1)
    print(f"ZAP: {len(alertas)} alertas -> {cfg['dast']['zap']['output_json']}")
    return len(alertas)


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("3-dast") as ctx:
        version = wait_for_api(cfg)
        provenance.record_tool_version("OWASP ZAP", version, source=cfg["docker"]["images"]["zap"])
        reset_session(cfg)
        configure(cfg)
        record_scan_rules(cfg)
        prepare_crawler_file(cfg)
        run_crawler(cfg)

        with provenance.stage("3c-dast-active-scan") as sctx:
            resultado = active_scan(cfg)
            sctx["detail"] = f"scan {resultado['scan_id']} en {resultado['elapsed_s']}s"

        total = export_alerts(cfg)
        ctx["detail"] = f"ZAP {version}; {total} alertas; escaneo {resultado['elapsed_s']}s"
