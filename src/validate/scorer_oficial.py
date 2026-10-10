"""Validacion independiente de las metricas con el scorer oficial del Benchmark.

Esta etapa no forma parte del pipeline y no modifica ningun resultado: sirve
para comprobar que las cifras que calcula src/evaluate/metrics.py coinciden con
las que produce la herramienta oficial del proyecto OWASP Benchmark
(BenchmarkUtils), que es la misma que genera los scorecards publicados.

Que hace:
  1. Prepara results/scorecard_oficial/ con el expectedresults del Benchmark y
     los ficheros de resultados de cada motor, renombrados con la convencion que
     espera el scorer (Benchmark_1.2-<motor>-v<version>.<ext>).
  2. Lanza org.owasp:benchmarkutils-maven-plugin:create-scorecard dentro de la
     imagen tft-crawler:1.2, que ya trae BenchmarkUtils instalado. El scorer
     emite un CSV por motor con el veredicto de cada uno de los 2740 casos.
  3. Recalcula TP/FP/FN/TN sobre esos CSV y los compara con results/metrics.csv,
     escribiendo results/validacion_scorer_oficial.csv.

Solo se validan las configuraciones C0 (cada motor por separado), que son las
unicas que el scorer oficial puede reproducir: las uniones C1-C3 y la
confirmacion cruzada C4 son aportacion de este trabajo y no existen como
concepto en BenchmarkUtils. Validar C0 es lo que importa, porque C1-C4 se
construyen con el mismo codigo de evaluacion sobre los mismos hallazgos.

Dos detalles de formato, ambos sin perdida ni alteracion de datos:

  - ZAP: el parser oficial (ZapJsonReader) acepta el formato "antiguo" de ZAP,
    un objeto con la clave "vulnerabilities" que contiene los mismos objetos de
    alerta que devuelve la API de ZAP. results/dast/zap.json guarda exactamente
    esos objetos bajo la clave "alerts", asi que la conversion es un renombrado
    de la clave raiz.

  - SpotBugs: el parser oficial (FindbugsReader) lee el XML nativo de SpotBugs,
    mientras que la etapa 2 exporta SARIF. Hay que regenerar el informe en XML
    con la misma invocacion Maven (mismo perfil, mismo effort y threshold) sobre
    el mismo bytecode ya compilado en la imagen tft-benchmark:1.2.
"""

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Any

from ..common import provenance
from ..common.config import host_project_dir, repo_root
from ..common.shell import run

DIRECTORIO = "results/scorecard_oficial"
SALIDA = "results/validacion_scorer_oficial.csv"
SALIDA_POR_CASO = "results/validacion_scorer_oficial_por_caso.csv"

# Nombre que el scorer da a cada motor -> configuracion equivalente en metrics.csv
MOTORES = {
    "Semgrep_OSS_v1.180.0": "C0-semgrep",
    "SBwFindSecBugs_v1.14.0": "C0-spotbugs",
    "OWASP_ZAP_v2.15.0": "C0-zap",
}

CLAVES = ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "benchmark_score")
RECUENTOS = ("tp", "fp", "fn", "tn")

CONFIG_SCORER = """\
# Generado por src/validate/scorer_oficial.py. Solo para la validacion externa.
expectedresults: expectedresults-1.2.csv
resultsfileordir: results
focustool: none
anonymousmode: false
averageonlymode: false
mixedmode: false
cwecategoryname: Vulnerabilities
tprlabel: TPR
includeprojectlink: false
includeprecision: true
"""


def _host(relpath: str) -> str:
    return f"{host_project_dir()}/{relpath}"


def convierte_zap(origen: Path, destino: Path) -> int:
    """Renombra la clave raiz 'alerts' a 'vulnerabilities'. Devuelve nº de alertas."""
    with open(origen, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    alertas = doc["alerts"]
    with open(destino, "w", encoding="utf-8") as fh:
        json.dump({"vulnerabilities": alertas}, fh)
    return len(alertas)


def regenera_spotbugs_xml(cfg: dict[str, Any], destino: Path) -> None:
    """Relanza SpotBugs+FindSecBugs pidiendo el XML nativo que lee el scorer.

    Misma imagen, mismo perfil y mismos parametros que la etapa 2: lo unico que
    cambia es el formato del informe. El plugin escribe target/spotbugsXml.xml,
    que se copia al directorio de resultados del scorer.
    """
    sb = cfg["sast"]["spotbugs"]
    script = "\n".join(
        [
            "set -e",
            "mvn -B -Pfindsecbugs -DskipTests -Dspotless.apply.skip=true compile"
            f" -Dspotbugs.effort={sb['effort']} -Dspotbugs.threshold={sb['threshold']}"
            " > /tmp/sb.log 2>&1 || { tail -40 /tmp/sb.log; exit 1; }",
            f"cp /benchmark/target/spotbugsXml.xml /out/{destino.name}",
        ]
    )
    relativa = destino.parent.relative_to(repo_root()).as_posix()
    run(
        [
            "docker", "run", "--rm",
            "-v", f"{_host(relativa)}:/out",
            "-e", "MAVEN_OPTS=-Xmx4g",
            "--entrypoint", "bash",
            "tft-benchmark:1.2", "-c", script,
        ],
        "validate-spotbugs-xml",
        timeout=1800,
    )


def prepara(cfg: dict[str, Any]) -> Path:
    """Monta el directorio de trabajo del scorer con los tres ficheros."""
    repo = repo_root()
    base = repo / DIRECTORIO
    resultados = base / "results"
    resultados.mkdir(parents=True, exist_ok=True)

    shutil.copy(repo / cfg["benchmark"]["expected_results_csv"], base)
    (base / "scoringconfig.yaml").write_text(CONFIG_SCORER, encoding="utf-8")

    shutil.copy(
        repo / cfg["sast"]["semgrep"]["output_sarif"],
        resultados / "Benchmark_1.2-semgrep-v1.180.0.sarif",
    )
    n = convierte_zap(
        repo / cfg["dast"]["zap"]["output_json"],
        resultados / "Benchmark_1.2-ZAP-v2.15.0.json",
    )
    print(f"  ZAP: {n} alertas reformateadas para el parser oficial")

    xml = resultados / "Benchmark_1.2-findsecbugs-v1.14.0.xml"
    if not xml.exists():
        print("  SpotBugs: regenerando el informe en XML nativo (~8 min)", flush=True)
        regenera_spotbugs_xml(cfg, xml)
    print(f"  SpotBugs: {xml.name} ({xml.stat().st_size / 1e6:.1f} MB)")
    return base


def lanza_scorer() -> None:
    """Ejecuta create-scorecard de BenchmarkUtils dentro de la imagen del crawler."""
    scorecard = repo_root() / DIRECTORIO / "scorecard"
    if scorecard.exists():
        shutil.rmtree(scorecard)
    run(
        [
            "docker", "run", "--rm",
            "-v", f"{_host(DIRECTORIO)}:/score",
            "-w", "/score",
            "-e", "MAVEN_OPTS=-Xmx6G",
            "--entrypoint", "mvn",
            "tft-crawler:1.2",
            "-B", "-Djava.awt.headless=true",
            "-DconfigFile=/score/scoringconfig.yaml",
            "org.owasp:benchmarkutils-maven-plugin:1.3:create-scorecard",
        ],
        "validate-scorer",
        timeout=3600,
    )


def lee_scorecard_csv(ruta: Path) -> dict[tuple[str, int], tuple[bool, bool]]:
    """Lee el CSV por caso del scorer: (caso, cwe) -> (es_vulnerable, lo_detecto)."""
    filas: dict[tuple[str, int], tuple[bool, bool]] = {}
    with open(ruta, "r", encoding="utf-8") as fh:
        for linea in fh:
            if linea.startswith("#") or not linea.strip():
                continue
            campos = [c.strip() for c in linea.split(",")]
            if len(campos) < 5:
                continue
            caso, _categoria, cwe, real, detectado = campos[:5]
            filas[(caso, int(cwe))] = (real == "true", detectado == "true")
    return filas


def metricas(filas: dict[tuple[str, int], tuple[bool, bool]]) -> dict[str, float]:
    tp = sum(1 for real, det in filas.values() if real and det)
    fp = sum(1 for real, det in filas.values() if not real and det)
    fn = sum(1 for real, det in filas.values() if real and not det)
    tn = sum(1 for real, det in filas.values() if not real and not det)
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": tpr, "f1": f1,
        "benchmark_score": tpr - fpr,
    }


def mis_totales() -> dict[str, dict[str, str]]:
    """Lee la fila TOTAL de cada configuracion de results/metrics.csv."""
    with open(repo_root() / "results/metrics.csv", "r", encoding="utf-8", newline="") as fh:
        return {f["configuracion"]: f for f in csv.DictReader(fh) if f["cwe"] == "TOTAL"}


def compara() -> list[dict[str, Any]]:
    """Compara, metrica a metrica, el scorer oficial con results/metrics.csv.

    Los recuentos (TP/FP/FN/TN) se comparan como enteros exactos. Los ratios se
    comparan a 4 decimales, que es la precision con la que metrics.csv los
    guarda; el scorer oficial muestra 3 en sus scorecards, pero aqui se
    recalculan desde su CSV por caso, asi que hay precision completa en los dos
    lados y no se encadenan dos redondeos.
    """
    base = repo_root() / DIRECTORIO / "scorecard"
    mias = mis_totales()
    filas: list[dict[str, Any]] = []
    for sufijo, config in MOTORES.items():
        archivo = base / f"Benchmark_v1.2_Scorecard_for_{sufijo}.csv"
        if not archivo.exists():
            raise RuntimeError(f"El scorer no genero {archivo.name}")
        por_caso = lee_scorecard_csv(archivo)
        if len(por_caso) != 2740:
            raise RuntimeError(f"{archivo.name} tiene {len(por_caso)} casos, se esperaban 2740")
        of = metricas(por_caso)
        mi = mias[config]
        for clave in CLAVES:
            es_recuento = clave in RECUENTOS
            columna = clave.upper() if es_recuento else clave
            if es_recuento:
                v_of, v_mi = int(of[clave]), int(mi[columna])
            else:
                v_of, v_mi = round(of[clave], 4), round(float(mi[columna]), 4)
            filas.append(
                {
                    "configuracion": config,
                    "motor_en_el_scorer": sufijo,
                    "metrica": clave,
                    "scorer_oficial": v_of,
                    "mi_pipeline": v_mi,
                    "coincide": "si" if v_of == v_mi else "NO",
                }
            )
    return filas


def compara_por_caso(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Comprueba la coincidencia caso a caso, no solo la de los totales.

    Que los recuentos globales cuadren no demuestra por si solo que los dos
    scorers marquen los mismos casos: podrian compensarse errores. Aqui se
    comparan los conjuntos de pares (caso, CWE) detectados, que es la
    afirmacion fuerte.

    Para que la comparacion sea de igual a igual hay que aplicar la unidad de
    puntuacion del Benchmark: cada caso se puntua solo contra el CWE de su
    propia categoria. Un hallazgo de CWE 327 dentro de un caso de la categoria
    sqli (CWE 89) no es un falso positivo de SQLi, simplemente no entra en el
    recuento de ninguna categoria. El scorer oficial lo descarta al construir su
    CSV; mi conjunto de detecciones lo conserva y es evalua() quien lo ignora al
    recorrer solo los casos de cada categoria. Por eso aqui se filtra igual: sin
    ese filtro mi conjunto es un superconjunto del oficial, aunque las metricas
    resultantes sean identicas.
    """
    from ..evaluate.metrics import carga_verdad, configuraciones, fuente_hallazgos

    with open(fuente_hallazgos(), "r", encoding="utf-8", newline="") as fh:
        filas_hallazgos = list(csv.DictReader(fh))
    mis_confs = configuraciones(filas_hallazgos, cfg)
    verdad = carga_verdad(cfg)

    base = repo_root() / DIRECTORIO / "scorecard"
    resumen: list[dict[str, Any]] = []
    for sufijo, config in MOTORES.items():
        por_caso = lee_scorecard_csv(base / f"Benchmark_v1.2_Scorecard_for_{sufijo}.csv")
        oficiales = {par for par, (_real, det) in por_caso.items() if det}
        mias = {
            (caso, cwe)
            for caso, cwe in mis_confs[config]["detecciones"]
            if caso in verdad and verdad[caso]["cwe"] == cwe
        }
        resumen.append(
            {
                "configuracion": config,
                "detecciones_scorer_oficial": len(oficiales),
                "detecciones_mi_pipeline": len(mias),
                "solo_en_el_oficial": len(oficiales - mias),
                "solo_en_el_mio": len(mias - oficiales),
                "coinciden_exactamente": "si" if oficiales == mias else "NO",
            }
        )
    return resumen


def escribe(filas: list[dict[str, Any]], destino: Path) -> Path:
    with open(destino, "w", encoding="utf-8", newline="") as fh:
        escritor = csv.DictWriter(fh, fieldnames=list(filas[0]))
        escritor.writeheader()
        escritor.writerows(filas)
    return destino


def run_stage(cfg: dict[str, Any]) -> None:
    with provenance.stage("9-validacion-scorer-oficial") as ctx:
        utils = cfg["benchmark"]["benchmark_utils"]
        provenance.record_tool_version(
            "BenchmarkUtils (scorer oficial)",
            str(utils.get("version", "1.3")),
            source=f"commit {utils['commit']}",
        )
        prepara(cfg)
        print("  lanzando create-scorecard de BenchmarkUtils", flush=True)
        lanza_scorer()
        filas = compara()
        escribe(filas, repo_root() / SALIDA)

        recuentos = [f for f in filas if f["metrica"] in RECUENTOS]
        ok_recuentos = sum(1 for f in recuentos if f["coincide"] == "si")
        ok_todas = sum(1 for f in filas if f["coincide"] == "si")

        actual = None
        for f in filas:
            if f["configuracion"] != actual:
                actual = f["configuracion"]
                print(f"\n  --- {actual} ---")
                print(f"  {'metrica':<18}{'oficial':>10}{'mio':>10}")
            marca = "" if f["coincide"] == "si" else "  <-- DIFIERE"
            print(f"  {f['metrica']:<18}{f['scorer_oficial']:>10}{f['mi_pipeline']:>10}{marca}")

        print("\n  --- coincidencia caso a caso ---")
        por_caso = compara_por_caso(cfg)
        escribe(por_caso, repo_root() / SALIDA_POR_CASO)
        print(f"  {'config':<14}{'oficial':>9}{'mio':>9}{'solo of.':>10}{'solo mio':>10}{'igual':>8}")
        for r in por_caso:
            print(
                f"  {r['configuracion']:<14}{r['detecciones_scorer_oficial']:>9}"
                f"{r['detecciones_mi_pipeline']:>9}{r['solo_en_el_oficial']:>10}"
                f"{r['solo_en_el_mio']:>10}{r['coinciden_exactamente']:>8}"
            )
        ok_casos = sum(1 for r in por_caso if r["coinciden_exactamente"] == "si")

        print(
            f"\n  recuentos TP/FP/FN/TN exactos: {ok_recuentos}/{len(recuentos)}"
            f"\n  metricas coincidentes:         {ok_todas}/{len(filas)}"
            f"\n  motores identicos caso a caso: {ok_casos}/{len(por_caso)}"
            f"\n  Detalle en {SALIDA} y {SALIDA_POR_CASO}"
        )
        ctx["detail"] = (
            f"{ok_todas}/{len(filas)} metricas coinciden con BenchmarkUtils; "
            f"recuentos exactos {ok_recuentos}/{len(recuentos)}; "
            f"coincidencia caso a caso {ok_casos}/{len(por_caso)}"
        )
