# Arquitectura del sistema: qué se instala, por qué, y cómo circula el dato

Este documento describe el sistema construido para el trabajo: qué componentes lo
forman, qué justifica cada elección, cómo se encadenan las etapas y qué produce.
Está pensado como material de base para el capítulo de diseño e implementación de
la memoria, y como manual para quien tenga que ejecutarlo o auditarlo.

---

## 1. Qué hace el sistema, en un párrafo

El sistema automatiza la búsqueda de vulnerabilidades en una aplicación web
combinando tres analizadores, y añade una etapa propia que intenta **confirmar
dinámicamente** cada hallazgo del análisis estático antes de darlo por válido. La
hipótesis de trabajo es que un hallazgo estático que no produce ningún cambio
observable en la respuesta HTTP cuando se le ataca es, probablemente, un falso
positivo. El sistema se evalúa sobre OWASP Benchmark v1.2, una aplicación Java de
2.740 casos de prueba con la solución conocida, lo que permite medir con exactitud
cuánto acierta y cuánto se equivoca.

El resultado de una ejecución no es solo una lista de vulnerabilidades: es una
lista **con una medida de su propio error**, que es lo que permite decidir si se
puede confiar en ella.

---

## 2. Principio de diseño: nada se instala en el sistema anfitrión

**Todo se ejecuta en contenedores Docker, incluido el propio orquestador.** En el
equipo donde se ejecuta no se instala Java, ni Maven, ni Python, ni ninguna de las
herramientas de análisis. El único requisito es Docker.

Esta decisión no es de comodidad, es de **reproducibilidad**, y era obligada en un
trabajo cuya tesis depende de cifras:

1. **Las versiones quedan fijadas en un fichero, no en un equipo.** Cada imagen se
   declara con su etiqueta exacta en `configs/pipeline.yml`; ninguna usa `latest`.
   Quien repita el experimento obtiene las mismas versiones de herramienta, no
   «las que tuviera instaladas».
2. **El resultado del análisis estático depende de la versión del analizador.** Un
   Semgrep distinto trae reglas distintas y produce otras cifras. Sin fijarlo, las
   métricas no serían comparables ni consigo mismas.
3. **El código analizado y el código servido son el mismo.** SpotBugs se ejecuta
   *dentro* de la imagen de la aplicación, sobre el bytecode ya compilado que
   Tomcat está sirviendo por HTTP. Si se analizara en otro sitio, no habría
   garantía de que el fichero y la línea que señala el hallazgo correspondan a lo
   que responde la URL que se ataca, y toda la etapa de confirmación cruzada
   perdería sentido.

### Cómo un contenedor lanza otros contenedores

El orquestador necesita arrancar Semgrep, SpotBugs y ZAP. Se resuelve con el
patrón *Docker-outside-of-Docker*: se le monta el socket del demonio Docker del
anfitrión (`/var/run/docker.sock`), de modo que los contenedores que lanza son
**hermanos** suyos, no hijos, y los gestiona el mismo demonio.

Esto tiene una consecuencia práctica que conviene conocer porque es fuente de
errores: cuando el orquestador pide montar un directorio, la ruta la resuelve el
demonio del anfitrión, **no** el sistema de ficheros del orquestador. Por eso el
proyecto exige la variable `TFT_HOST_PROJECT_DIR` con la ruta del proyecto *en el
anfitrión*; sin ella, los montajes apuntarían a rutas internas que el demonio no
conoce.

---

## 3. Inventario: qué se instala y por qué

### 3.1. Imágenes de contenedor

| Imagen | Base | Papel | Por qué esta y no otra |
|---|---|---|---|
| `tft-benchmark:1.2` | `maven:3.9.16-eclipse-temurin-17` | La aplicación bajo análisis, en HTTPS `:8443` | JDK 17 porque el `pom.xml` del Benchmark usa `--add-exports` en `.mvn/jvm.config`, que no existe en JDK 8; con JDK 8 la compilación aborta |
| `tft-crawler:1.2` | `tft-benchmark:1.2` | Rastreador oficial y puntuador oficial del Benchmark | Parte de la imagen de la aplicación para reutilizar sus fuentes y su caché de dependencias Maven |
| `tft-orchestrator:1.0` | `python:3.11.17-slim` | Ejecuta `run_all.py` y coordina las etapas | Lleva además `docker-ce-cli` y `docker-compose-plugin` para poder lanzar los contenedores hermanos |
| `semgrep/semgrep:1.180.0` | oficial | Análisis estático sobre el código fuente | Imagen oficial, versión fijada |
| `zaproxy/zap-stable:2.15.0` | oficial | Análisis dinámico en modo demonio | Imagen oficial, versión fijada |

### 3.2. Componentes dentro de las imágenes

**Tomcat 9.0.122** se empaqueta dentro de la imagen de la aplicación, descargado de
`archive.apache.org` y no del mirror de distribución. Motivo: los mirrors retiran
las versiones antiguas, de modo que una imagen que dependiera del mirror dejaría
de construirse en cuanto saliera una versión nueva. El archivo histórico no
cambia.

**HSQLDB y ApacheDS (LDAP)** los arranca el propio Benchmark en su fase `package`.
No son una elección del trabajo: son las dependencias que los casos de prueba de
inyección SQL y de inyección LDAP necesitan para ser realmente explotables. Sin
ellas, esos casos responderían con un error de conexión y cualquier ataque
parecería «no confirmado» por el motivo equivocado.

**BenchmarkUtils 1.3**, fijado por commit, aporta dos cosas distintas:

- el **rastreador oficial**, que recorre los 2.740 casos con la entrada que cada
  uno espera (etapa 3);
- el **puntuador oficial**, el mismo programa que genera los *scorecards* que OWASP
  publica, que se usa para validar las métricas de forma independiente.

### 3.3. Dependencias de Python

Solo cinco dependencias directas, cada una con un propósito único:

| Paquete | Para qué |
|---|---|
| `PyYAML` | Leer `configs/pipeline.yml`, la configuración única |
| `requests` | Hablar con la API de ZAP y comprobar que la aplicación responde |
| `numpy` | Vector de rasgos de las respuestas HTTP |
| `scikit-learn` | DBSCAN del agrupamiento |
| `matplotlib` | Generar las figuras en PNG |

`requirements.txt` es el bloqueo completo (23 paquetes con versión exacta,
generado con `pip freeze` dentro de la imagen). `requirements.in` lista solo las
cinco directas con su propósito anotado. Deliberadamente **no** se usa el cliente
Python de ZAP: la API se consume con `requests` sobre un cliente mínimo de unas
treinta líneas, lo que evita una dependencia más y deja a la vista exactamente qué
llamadas se hacen.

### 3.4. Analizadores: qué configuración y por qué

**Semgrep OSS 1.180.0**, con los conjuntos de reglas `p/java` y `p/owasp-top-ten`.
Analiza el código fuente y exporta SARIF, un formato estándar que evita escribir un
analizador sintáctico propio.

**SpotBugs 4.10.4.1 + FindSecBugs 1.14.0**, invocados a través del perfil
`findsecbugs` que **el propio `pom.xml` del Benchmark ya define**, con `effort=Max`
y `threshold=Low`. Usar el perfil del proyecto en lugar de una configuración propia
es intencionado: así se aplican los filtros de inclusión y exclusión que el
Benchmark considera correctos para su propia evaluación, y las versiones son las
que el proyecto declara, no las que uno elija.

Un detalle de implementación con consecuencias en los resultados: la compilación se
lanza con `-Dspotless.apply.skip=true`. El plugin *spotless* reformatea el código
fuente, y un reformateo **desplaza los números de línea**. Como la etapa de mapeo
asocia cada hallazgo a su caso de prueba, y el informe final señala fichero y
línea, dejar que el código se reformatee entre el análisis y la lectura invalidaría
esas referencias.

**OWASP ZAP 2.15.0** en modo demonio, controlado por su API JSON. Dos ajustes no
triviales:

- **Vectores de inyección ampliados a 31** (query string, cuerpo POST, cookies,
  cabeceras y ruta de URL). ZAP de serie no inyecta en cookies ni en cabeceras, y
  en el Benchmark **un tercio de los casos recibe la entrada precisamente por ahí**.
  Sin este ajuste, ese tercio parecería no explotable por una limitación de la
  configuración, no de la aplicación.
- **`-Xmx3g`**. Con la memoria por defecto, ZAP deja de responder a su propia API a
  mitad del escaneo completo y el contenedor pasa a estado no saludable.

---

## 4. Las nueve etapas y qué produce cada una

```
1 deploy    ──► aplicación en https://localhost:8443/benchmark/
2 sast      ──► results/sast/semgrep.sarif, spotbugs.sarif
3 dast      ──► results/dast/zap.json  (+ el XML del rastreo)
4 normalize ──► results/hallazgos_normalizados.csv
5 map       ──► results/hallazgos_mapeados.csv
6 verify    ──► results/hallazgos_verificados.csv, respuestas_zap.csv
7 cluster   ──► results/hallazgos.csv
8 evaluate  ──► results/metrics.csv, figuras/
9 informe   ──► results/INFORME.html, results/lista_revision.csv
```

**1. Despliegue.** Arranca la aplicación y espera a que responda de verdad por
HTTPS, no solo a que el contenedor exista.

**2. Análisis estático.** Semgrep sobre el código fuente y SpotBugs+FindSecBugs
sobre el bytecode. Los dos exportan SARIF. Son dos motores con técnicas distintas
(patrones sintácticos frente a análisis de flujo de datos sobre bytecode), y
compararlos es parte del experimento.

**3. Análisis dinámico.** ZAP rastrea la aplicación usando el **rastreador oficial
del Benchmark**, que conoce la entrada que espera cada caso, y después lanza un
escaneo activo completo. El rastreador se hace pasar por el proxy de ZAP, lo que
obliga a importar en tiempo de ejecución la autoridad certificadora raíz de ZAP en
el almacén de confianza de Java: ZAP intercepta TLS y, sin ese paso, el rastreo
falla con un error de handshake.

**4. Normalización.** Las tres salidas, con formatos distintos, se llevan a un
esquema común: `{motor, CWE, archivo, línea, ruta_http, parámetro, severidad}`.
Aquí se resuelven también las equivalencias de CWE, porque las herramientas no
siempre usan el mismo número para lo mismo (por ejemplo 326 y 327 para cifrado
débil).

**5. Mapeo estático → HTTP.** Asocia cada hallazgo estático a la URL y al parámetro
por los que se le puede atacar. La fuente es `benchmark-crawler-http.xml`, el mapa
que el propio Benchmark usa, que da la URL y el **vector exacto** de cada caso
(parámetro GET, parámetro de formulario, cabecera o cookie). Se eligió frente a
interpretar las anotaciones `@WebServlet` del código porque el vector es un dato
que la anotación no proporciona y que la etapa siguiente necesita.

> **Límite de validez externa, importante.** Esta es la única etapa que **no es
> trasladable tal cual a una aplicación real**: depende de un fichero propio del
> banco de pruebas y de identificar el caso por el nombre del fichero. El mecanismo
> de confirmación de las etapas 6 y 7 sí es independiente del lenguaje, porque solo
> necesita una ruta y un parámetro; lo que no es genérico es *cómo se obtiene esa
> correspondencia*. Fuera del Benchmark habría que derivarla del enrutado del
> framework, de instrumentación o de un rastreo con cobertura, y ninguna de esas
> vías se ha evaluado en este trabajo.

**6. Confirmación cruzada.** Por cada par (ruta, CWE) con hallazgos estáticos se
lanza un escaneo activo **dirigido solo a esa URL**, con una política que contiene
**únicamente las reglas de ese CWE**, para que una alerta de otra familia no pueda
confirmar el hallazgo. De cada par se recogen dos cosas: si ZAP levantó alerta de
ese CWE, y los rasgos de todas las respuestas HTTP que ZAP provocó.

**Las pruebas de ataque las genera íntegramente ZAP.** El sistema no contiene
ningún *payload* escrito a mano. Es una decisión metodológica: los ataques
provienen de una herramienta reconocida y auditable, no del criterio del autor, lo
que hace el resultado defendible y reproducible.

**7. Agrupamiento de respuestas.** Sobre las respuestas ya capturadas, sin generar
tráfico nuevo. Tres rasgos por respuesta (código de estado, longitud y similitud
de contenido con la respuesta de referencia), estandarizados y agrupados con
DBSCAN. Si alguna respuesta provocada por el ataque queda fuera del grupo de la
referencia, el comportamiento cambió y el hallazgo queda **confirmado**; si todas
caen en el mismo grupo, queda **descartado**.

> **Precisión terminológica.** La referencia es la respuesta de la aplicación a la
> **entrada válida** del rastreador, no una «página de rechazo» obtenida con
> entradas inválidas. La diferencia no es menor: con esta referencia, cualquier
> *payload* que altere la salida se separa del grupo **aunque la aplicación lo haya
> saneado correctamente**. Esa es la razón directa por la que el filtro no
> discrimina en XSS reflejado, donde el ataque se refleja en la respuesta por
> definición.

Un hallazgo sin ruta HTTP, o de un CWE para el que ZAP no tiene reglas, queda
**no verificable** y **se conserva**. Descartarlo atribuiría al hallazgo una
limitación de la herramienta dinámica.

**8. Evaluación.** Contra `expectedresults-1.2.csv`. La unidad es el par (caso,
CWE), igual que en el puntuador oficial: varios avisos sobre el mismo caso y el
mismo tipo de fallo son una sola detección.

**9. Informe.** Reúne todo en `results/INFORME.html` y en la lista de trabajo
`results/lista_revision.csv`.

### Análisis complementarios, fuera del flujo normal

| Comando | Qué comprueba |
|---|---|
| `--stages validate` | Que las métricas coinciden con el puntuador oficial de OWASP |
| `--stages sensibilidad` | Cuánto depende el resultado de los parámetros del agrupamiento |
| `--stages carga` | El coste de revisión sobre el informe completo, no solo sobre los casos puntuables |

---

## 5. Cómo se ejecuta y dónde sale el informe

### Requisitos

Docker con el motor en marcha, unos 8 GB de RAM disponibles para la máquina
virtual de Docker, ~6 GB de disco y acceso a Internet en la primera ejecución.

**El reloj del sistema debe estar sincronizado.** Un desfase de pocos días
invalida los certificados TLS del registro de Docker y aborta todas las descargas
con un error que no menciona la hora.

### Ejecución completa

```powershell
# 1. Generar .env con la ruta del proyecto en el anfitrión
#    (debe contener: TFT_HOST_PROJECT_DIR=D:/ruta/al/proyecto)

# 2. Construir las imágenes (solo la primera vez, ~15 min)
docker compose build

# 3. Ejecutar las nueve etapas
docker compose run --rm orchestrator python run_all.py --all
```

Una ejecución completa tarda entre **8 y 11 horas**, casi todo en la etapa 6, que
lanza unos 2.900 escaneos independientes.

Para ejecutar solo una parte:

```powershell
docker compose run --rm orchestrator python run_all.py --list
docker compose run --rm orchestrator python run_all.py --stages deploy,sast
```

### Dónde sale el informe

Al terminar, **lo que hay que abrir son dos ficheros**:

```powershell
# El informe, en el navegador
Invoke-Item results\INFORME.html

# La lista de trabajo, en Excel o en el editor
Invoke-Item results\lista_revision.csv
```

`INFORME.html` responde, en una sola página: qué se analizó, cuántos ítems hay que
revisar y de qué tipo, cuánto acierta el sistema medido contra la solución
conocida, cuánto trabajo ahorra de verdad, y dónde está cada fichero.

`lista_revision.csv` es la lista accionable, ordenada por prioridad:

| prioridad | significa |
|---|---|
| 1 | **Confirmado.** El ataque cambió el comportamiento de la aplicación. Revisar primero |
| 2 | **No verificable.** No se pudo comprobar dinámicamente. Se conserva a propósito |
| 3 | **Observado por el analizador dinámico.** Lo encontró ZAP por sí mismo |

Lo descartado **no aparece en la lista**, pero no se borra: sigue en
`results/hallazgos.csv` con su veredicto y su evidencia, de modo que cualquier
descarte se puede auditar uno a uno.

### Dónde va todo lo demás

| Ruta | Contenido |
|---|---|
| `results/INFORME.html` | El informe para leer |
| `results/lista_revision.csv` | La lista de trabajo |
| `results/metrics.csv` | Métricas por configuración y por CWE |
| `results/hallazgos.csv` | Todos los avisos, con veredicto y evidencia |
| `results/figuras/*.png` | Gráficas |
| `results/entorno.txt` | Fecha, hardware, versiones y tiempo por etapa |
| `results/sast/`, `results/dast/` | Salida **original** de cada herramienta, sin tocar |
| `results/provenance.jsonl` | Registro crudo de la ejecución |
| `logs/` | Salida completa de cada herramienta (no se versiona: cientos de MB) |

Las salidas originales se conservan deliberadamente: permiten rehacer cualquier
etapa posterior sin repetir el análisis, y permiten a un tercero comprobar que la
normalización no introdujo nada.

### Cómo se sigue una ejecución en marcha

La etapa 6 no escribe sus ficheros hasta el final, así que la fecha de los
resultados no sirve para ver el progreso. Tres señales que sí:

```powershell
# ¿Sigue trabajando?
docker ps --filter name=orchestrator --format "{{.Names}} {{.Status}}"

# ¿Por dónde va? Cada fila son 150 pares ya verificados
Import-Csv results\stage_times.csv |
  Where-Object { $_.stage -eq "3b-dast-crawl" } | Select-Object -Last 5

# ¿Genera tráfico? Este contador debe subir siempre
(Invoke-WebRequest -UseBasicParsing `
  "http://localhost:8090/JSON/core/view/numberOfMessages/?apikey=tft-zap-key").Content
```

---

## 6. Trazabilidad: por qué las cifras son comprobables

El trabajo sostiene afirmaciones numéricas, así que el sistema registra de dónde
sale cada una:

- **`results/provenance.jsonl`** anota cada versión de herramienta *tal como la
  herramienta se identificó a sí misma* durante la ejecución, con su fecha. El
  fichero `entorno.txt` se genera a partir de ahí: no declara ninguna versión que
  no se haya observado.
- **`results/stage_times.csv`** registra el tiempo de cada etapa, incluidos los
  intentos fallidos.
- El **código del Benchmark no se versiona**: se clona fijado a un commit
  declarado en `configs/pipeline.yml`. La versión v1.2 del Benchmark es la cabeza
  de `master`, no una etiqueta, así que fijar el commit es la única forma de que la
  ejecución sea repetible.
- Las **métricas están contrastadas con el puntuador oficial de OWASP**
  (BenchmarkUtils), con coincidencia exacta caso por caso en los tres motores sobre
  los 2.740 casos. Es la comprobación más fuerte disponible: no depende de que la
  metodología de puntuación se haya reimplementado bien.

---

## 7. Limitaciones que condicionan la lectura de los resultados

1. **El mapeo estático → HTTP depende del banco de pruebas** (apartado 4, etapa 5).
   Es la limitación más seria para la validez externa.
2. **ZAP 2.15 de serie solo cubre 6 de los 11 tipos de fallo evaluados.** Tiene
   reglas para path traversal, inyección de comandos, XSS, inyección SQL, XPath y
   cookie insegura. No las tiene para inyección LDAP (está en un complemento que no
   se instala) ni para cifrado débil, hash débil, aleatoriedad débil y violación de
   límite de confianza, que son propiedades del código y no se observan en una
   respuesta HTTP. Esos hallazgos quedan como no verificables y se conservan.
3. **El filtro no discrimina en XSS reflejado**, por la razón explicada en la
   etapa 7.
4. **El agrupamiento con DBSCAN no aporta nada medible sobre una simple prueba de
   invariancia de la respuesta.** Comprobado con una barrida de 30 combinaciones de
   sus dos parámetros: el resultado es idéntico en todas, y también idéntico al de
   la regla trivial sin DBSCAN. Es un resultado negativo, y está medido.
5. **Los hallazgos del analizador dinámico no pasan por el filtro**: se conservan
   como observación dinámica, porque confirmar una observación dinámica con otra
   observación dinámica sería circular. Lo medido es, por tanto, reducción de
   falsos positivos **del análisis estático**.
6. **La reducción de falsos positivos no es lo mismo que la reducción del trabajo
   del auditor.** La primera se mide sobre los casos que el Benchmark puntúa; la
   segunda, sobre todos los avisos del informe. El sistema mide las dos por
   separado (`results/carga_revision.csv`) precisamente porque no coinciden.
7. **Una sola aplicación, pública y sintética.** Los casos del Benchmark están
   aislados, tienen una ruta cada uno y su etiquetado es conocido y muy usado, de
   modo que el rendimiento de los analizadores sobre él puede no reflejar el que
   tendrían sobre una aplicación real.
8. **El analizador dinámico no es determinista.** El total de alertas varía en
   torno al 2 % entre ejecuciones, porque un escaneo activo depende de tiempos de
   respuesta.
