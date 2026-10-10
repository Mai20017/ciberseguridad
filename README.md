# Framework de reduccion de falsos positivos combinando SAST y DAST

Pipeline reproducible para evaluar, sobre **OWASP Benchmark v1.2 (Java)**, en que
medida la confirmacion cruzada de hallazgos estaticos con un escaneo dinamico
dirigido reduce los falsos positivos del analisis estatico.

Trabajo Fin de Titulo (VIU). Todas las cifras publicadas en `results/` proceden
de ejecuciones reales registradas en `results/provenance.jsonl`.

Por donde empezar:

- **[ARQUITECTURA.md](ARQUITECTURA.md)** — que se instala y por que, como circula el
  dato por las nueve etapas, como se ejecuta y **donde sale el informe**.
- **[GUIA-AUDITORIA.md](GUIA-AUDITORIA.md)** — como comprobar por tu cuenta que las
  cifras son reales, sin fiarte de nada.

## Arquitectura

Todo se ejecuta en contenedores, sin instalar ninguna herramienta en el sistema
anfitrion. El orquestador (Python 3.11) lanza los contenedores hermanos contra
el demonio Docker del host a traves del socket montado.

| Componente | Imagen | Papel |
|---|---|---|
| Benchmark | `tft-benchmark:1.2` (Maven 3.9.16 + JDK 17, Tomcat 9.0.122) | Aplicacion bajo analisis, HTTPS en `:8443` |
| Orquestador | `tft-orchestrator:1.0` (Python 3.11.17) | Ejecuta `run_all.py` y coordina las etapas |
| Semgrep | `semgrep/semgrep:1.180.0` | SAST, rulesets `p/java` y `p/owasp-top-ten` |
| SpotBugs + FindSecBugs | `tft-benchmark:1.2` (perfil `findsecbugs` del propio Benchmark) | SAST sobre el bytecode compilado |
| ZAP | `zaproxy/zap-stable:2.15.0` | DAST en modo daemon, controlado por API |

SpotBugs se ejecuta dentro de la imagen del Benchmark de forma deliberada: asi
analiza exactamente el mismo bytecode que Tomcat esta sirviendo por HTTP, y usa
las versiones y filtros que el propio `pom.xml` del Benchmark declara.

## Requisitos

- Docker (con el motor Linux en marcha). Nada mas: ni Java, ni Maven, ni Python
  en el anfitrion.
- Unos 8 GB de RAM disponibles para la VM de Docker y ~6 GB de disco.
- Acceso a Internet en la primera ejecucion (descarga de imagenes, dependencias
  Maven y rulesets de Semgrep).
- **El reloj del sistema debe estar sincronizado.** Un desfase de pocos dias
  invalida los certificados TLS del registro de Docker y aborta las descargas.

## Puesta en marcha

```sh
make env      # genera .env con la ruta del proyecto en el host
make build    # construye las imagenes
make all      # ejecuta las ocho etapas de punta a punta
```

O etapa por etapa:

```sh
make deploy   # 1. despliega el Benchmark y espera a que responda
make sast     # 2. Semgrep + SpotBugs/FindSecBugs
make dast     # 3. ZAP: rastreo y escaneo activo
```

Sin `make` (por ejemplo, en PowerShell) los equivalentes son:

```powershell
# .env debe contener: TFT_HOST_PROJECT_DIR=D:/ruta/al/proyecto
docker compose build
docker compose run --rm orchestrator python run_all.py --all
docker compose run --rm orchestrator python run_all.py --stages deploy,sast
docker compose run --rm orchestrator python run_all.py --list
```

`TFT_HOST_PROJECT_DIR` es obligatoria: los bind mounts de los contenedores
hermanos los resuelve el demonio Docker del host, que no conoce las rutas
internas del orquestador.

Una vez desplegado, el Benchmark queda en <https://localhost:8443/benchmark/>
con un certificado autofirmado (el navegador avisara; es lo esperado).

## Etapas del pipeline

| # | Etapa | Salida |
|---|---|---|
| 1 | Despliegue del Benchmark | contenedor `tft-benchmark` en `:8443` |
| 2 | SAST: Semgrep y SpotBugs+FindSecBugs | `results/sast/*.sarif` |
| 3 | DAST: ZAP en daemon (rastreo + escaneo activo) | `results/dast/zap.json` |
| 4 | Normalizacion al esquema comun | `results/hallazgos_normalizados.csv` |
| 5 | Mapeo SAST -> ruta HTTP, parametro y vector | `results/hallazgos_mapeados.csv` |
| 6 | Confirmacion cruzada dirigida con ZAP | `results/hallazgos_verificados.csv`, `results/respuestas_zap.csv` |
| 7 | Clustering de respuestas contra la linea base | `results/hallazgos.csv` |
| 8 | Evaluacion contra `expectedresults-1.2.csv` | `results/metrics.csv`, `results/resumen_hallazgos.csv`, `results/figuras/*.png` |
| 9 | Informe final legible y lista de trabajo | `results/INFORME.html`, `results/lista_revision.csv` |

Lo que hay que abrir al terminar son esos dos ultimos: `INFORME.html` en el
navegador y `lista_revision.csv` en una hoja de calculo.

Cada invocacion de `run_all.py` regenera ademas `results/entorno.txt` con las
versiones observadas, el hardware y el tiempo de cada etapa.

### Analisis complementarios (fuera de `--all`)

Tres comprobaciones que no producen resultados propios del pipeline sino que
miden su validez. Se lanzan por separado:

```bash
python run_all.py --stages validate       # contraste con el scorer oficial de OWASP
python run_all.py --stages sensibilidad   # barrida de eps y min_samples del agrupamiento
python run_all.py --stages carga          # carga de revision sobre el informe completo
```

| Analisis | Para que | Salida |
|---|---|---|
| `validate` | Comprobar que las metricas coinciden con BenchmarkUtils | `results/validacion_scorer_oficial*.csv`, `results/scorecard_oficial/` |
| `sensibilidad` | Medir cuanto depende el resultado de `eps` y `min_samples`, y compararlo con una regla trivial sin DBSCAN | `results/sensibilidad_clustering.csv`, `results/figuras/sensibilidad_eps.png` |
| `carga` | Medir el coste de revision sobre el informe que recibe el auditor, no solo sobre los pares puntuables | `results/carga_revision.csv` |

`sensibilidad` y `carga` no generan trafico: reutilizan las respuestas y los
hallazgos ya capturados, por lo que tardan segundos.

### Validacion externa de las metricas

Fuera del pipeline (no la incluye `--all`) hay una etapa que contrasta las cifras
de la etapa 8 con **BenchmarkUtils**, la herramienta de puntuacion oficial del
proyecto OWASP Benchmark, la misma que genera los scorecards publicados:

```bash
python run_all.py --stages validate
```

Le entrega a BenchmarkUtils las salidas originales de los tres motores y compara
su veredicto con `results/metrics.csv`. Resultado de la ejecucion registrada: las
**24 metricas de las tres configuraciones C0 coinciden** y los dos scorers marcan
**exactamente los mismos casos** (0 diferencias en ambos sentidos sobre los 2740
casos). Salida en `results/validacion_scorer_oficial.csv`,
`results/validacion_scorer_oficial_por_caso.csv` y los scorecards HTML y PNG de
`results/scorecard_oficial/scorecard/`.

Solo C0 es validable: las uniones C1-C3 y la confirmacion cruzada C4 son
aportacion de este trabajo y no existen como concepto en BenchmarkUtils. Se
calculan con el mismo codigo de evaluacion y sobre los mismos hallazgos, por lo
que validar C0 valida el mecanismo.

## Configuraciones del experimento

| Config | Contenido |
|---|---|
| C0 | cada motor por separado: Semgrep, SpotBugs+FindSecBugs, ZAP |
| C1 | union de los motores SAST |
| C2 | union de los motores DAST |
| C3 | union de todos los motores |
| C4 | C3 + confirmacion cruzada + clustering |
| C4a | C3 + solo la alerta de ZAP (ablacion: sin agrupamiento) |
| C4b | C3 + solo la separacion por agrupamiento (ablacion: sin alerta) |
| C4c | C3 + solo la invariancia de la respuesta (ablacion: sin DBSCAN ni alerta) |

Las tres ablaciones C4a-C4c existen porque C4 confirma un hallazgo cuando la
alerta **o** la separacion lo confirman, de modo que sin aislarlas no se puede
atribuir la reduccion de falsos positivos a ninguna de las dos.

La unidad de evaluacion es el par (caso de prueba, CWE), no el hallazgo: varios
hallazgos del mismo motor sobre el mismo caso y CWE cuentan como una sola
deteccion, igual que en el scorer oficial del Benchmark.

## Decisiones metodologicas que conviene conocer

- **Las pruebas de ataque las genera ZAP.** El pipeline no contiene ningun
  payload escrito a mano: la etapa 6 lanza un escaneo activo dirigido a cada URL
  con una politica que solo tiene las reglas del CWE del hallazgo, y la etapa 7
  agrupa las respuestas que ZAP provoco.
- **ZAP 2.15 de serie solo cubre 6 de los 11 CWE del Benchmark.** Tiene reglas
  para 22, 78, 79, 89, 643 y 614, pero no para 90 (inyeccion LDAP, vive en el
  add-on `ascanrulesBeta`, no instalado) ni para 327, 328, 330 y 501, que son
  propiedades del codigo y no se observan en la respuesta HTTP. Los hallazgos
  SAST de esos cinco CWE quedan **`no_verificable`**, nunca `descartado`:
  descartarlos atribuiria al hallazgo una limitacion del motor dinamico.
- **Hay que habilitar la inyeccion en cabeceras y cookies.** Por defecto ZAP
  solo inyecta en query string y datos POST (`TargetParamsInjectable=3`), y el
  Benchmark envia 657 casos por cabecera y 216 por cookie.
- **El mapeo SAST -> HTTP sale de `data/benchmark-crawler-http.xml`**, el mapa
  autoritativo del propio Benchmark, en lugar de inferirse de las anotaciones
  `@WebServlet`: indica el vector real de cada caso, que la anotacion no da.
- **Hay que desactivar `spotless:apply`** al compilar el Benchmark. Ademas de
  necesitar un repositorio git, reformatearia el codigo fuente y los numeros de
  linea de los hallazgos SAST dejarian de corresponder al commit analizado.
- **CSRF (CWE-352) no tiene ni un caso en el Benchmark v1.2**, por lo que su
  exclusion no elimina nada.

## Reproducibilidad

- El codigo del Benchmark **no se versiona**: se clona fijado al commit indicado
  en `configs/pipeline.yml` (`benchmark.commit`). El README del proyecto upstream
  declara que la release v1.2 es el HEAD de `master`, no un tag, por lo que fijar
  el commit es la unica forma de que la ejecucion sea repetible.
- Todas las imagenes estan fijadas por etiqueta de version exacta en
  `configs/pipeline.yml`; ninguna usa `latest`.
- Tomcat 9.0.122 se empaqueta en la imagen desde `archive.apache.org`, de modo
  que el arranque no depende de que el mirror siga publicando esa version.
- `requirements.txt` es el bloqueo completo (`pip freeze`) de las dependencias
  del orquestador; `requirements.in` lista solo las directas.
- `results/stage_times.csv` registra el tiempo de cada etapa y
  `results/provenance.jsonl` la fecha, el entorno y la version exacta que cada
  herramienta reporta de si misma.
- El codigo de evaluacion esta contrastado con el scorer oficial del Benchmark
  (ver «Validacion externa de las metricas»), de modo que las cifras no dependen
  de que la metodologia de puntuacion se haya reimplementado bien.

## Estructura

```
configs/pipeline.yml     Configuracion unica del pipeline (versiones, rutas, URLs)
docker/                  Dockerfiles del Benchmark y del orquestador
src/common/              Configuracion, ejecucion de procesos y registro de procedencia
src/deploy/              Etapa 1
src/sast/                Etapa 2
src/dast/                Etapa 3
src/normalize/           Etapa 4
src/mapping/             Etapa 5
src/verify/              Etapa 6
src/cluster/             Etapa 7
src/evaluate/            Etapa 8 y figuras
src/report/              Etapa 9: informe HTML y lista de trabajo
src/validate/            Validacion externa con el scorer oficial (fuera del pipeline)
results/                 Evidencia de las ejecuciones (se versiona)
logs/                    Salida cruda de las herramientas (no se versiona)
run_all.py               Punto de entrada del pipeline
```
