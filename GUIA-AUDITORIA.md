# Guia para entender y auditar este proyecto

Esta guia esta pensada para que cualquier persona con conocimientos basicos de
informatica pueda (a) entender que hace el proyecto, (b) ver por donde va una
ejecucion y (c) **comprobar por su cuenta que ninguna cifra esta inventada**.

No hace falta saber Python ni seguridad de aplicaciones. Todos los comandos son
para PowerShell en Windows, desde la carpeta del proyecto.

---

## 1. Que hace el proyecto, en un parrafo

Los analizadores de codigo (SAST) encuentran casi todos los fallos de seguridad,
pero se equivocan mucho: marcan como vulnerables trozos de codigo que no lo son.
Este proyecto comprueba cada uno de esos avisos **atacando de verdad** la
aplicacion por HTTP con OWASP ZAP (DAST): si el ataque provoca un cambio real en
el comportamiento, el aviso se da por bueno; si la aplicacion responde igual que
ante una entrada inofensiva, se descarta. Para medir si eso funciona se usa
OWASP Benchmark, una aplicacion Java de 2.740 casos de prueba en la que **ya se
sabe de antemano cuales son vulnerables de verdad**, asi que se puede contar
exactamente cuantos aciertos y cuantos falsos positivos comete cada estrategia.

---

## 2. Como veo por donde va una ejecucion

```powershell
# Lo que esta pasando ahora mismo (se actualiza solo; Ctrl+C para salir)
Get-Content logs\run-all.log -Wait -Tail 15

# Que etapas han terminado ya en esta ejecucion
Select-String -Path logs\run-all.log -Pattern "^=== "

# Cuanto tardo cada etapa (todas las ejecuciones, en orden)
Import-Csv results\stage_times.csv | Format-Table stage, duration_s, status, detail
```

Las ocho etapas, en orden, y cuanto tardan aproximadamente:

| # | Etapa | Que hace | Tiempo |
|---|---|---|---|
| 1 | deploy | Compila y arranca OWASP Benchmark en https://localhost:8443/benchmark/ | ~4 min |
| 2 | sast | Pasa Semgrep y SpotBugs+FindSecBugs sobre el codigo Java | ~10 min |
| 3 | dast | ZAP recorre los 2.740 casos y los ataca a todos | ~70 min |
| 4 | normalize | Pone los hallazgos de las tres herramientas en un formato comun | segundos |
| 5 | map | Averigua a que URL y parametro corresponde cada hallazgo | segundos |
| 6 | verify | Ataca con ZAP cada hallazgo, uno a uno, solo con las reglas de su CWE | ~4 h |
| 7 | cluster | Compara las respuestas al ataque con la respuesta normal de esa misma URL | segundos |
| 8 | evaluate | Cuenta aciertos y fallos contra la solucion conocida y dibuja las graficas | segundos |

La etapa 6 es la larga porque lanza unos 2.900 escaneos independientes. Avisa de
su progreso cada 100.

### Saber si la etapa 6 sigue viva y por donde va

La etapa 6 no escribe sus ficheros hasta el final, asi que la fecha de
`results/hallazgos_verificados.csv` no sirve para ver el progreso. Hay tres
senales que si sirven:

```powershell
# 1. ¿Sigue trabajando? Si no aparece nada, ha terminado (o ha fallado)
docker ps --filter name=orchestrator --format "{{.Names}} {{.Status}}"

# 2. ¿Por donde va? La etapa 6 rota la sesion de ZAP cada 150 escaneos y deja
#    una fila por rotacion, asi que cada fila son 150 pares ya verificados
Import-Csv results\stage_times.csv |
  Where-Object { $_.stage -eq "3b-dast-crawl" } |
  Select-Object -Last 5 started_at_utc, detail

# 3. ¿Esta generando trafico de verdad? Este contador debe subir siempre
(Invoke-WebRequest -UseBasicParsing `
  "http://localhost:8090/JSON/core/view/numberOfMessages/?apikey=tft-zap-key").Content
```

Cuando termina, la ultima fila de `results/stage_times.csv` es `8-evaluate` con
`status` = `ok`, y `results/metrics.csv` cambia de fecha.

---

## 3. Que hay en results/ y para que sirve cada cosa

| Fichero | Que contiene |
|---|---|
| `metrics.csv` | **La tabla de resultados.** Una fila por configuracion y por CWE |
| `validacion_scorer_oficial.csv` | **La comprobacion de que esa tabla es correcta**, contra la herramienta oficial de OWASP |
| `validacion_scorer_oficial_por_caso.csv` | Lo mismo, pero caso a caso en vez de por totales |
| `scorecard_oficial/scorecard/` | Los scorecards HTML y PNG que genera la herramienta oficial |
| `hallazgos.csv` | Todos los hallazgos, uno por fila, con su veredicto final |
| `resumen_hallazgos.csv` | El recuento: cuantos confirmados, descartados y no verificables |
| `entorno.txt` | Fecha, hardware, version exacta de cada herramienta y tiempo por etapa |
| `figuras/*.png` | Las graficas de barras |
| `stage_times.csv` | Cuanto tardo cada etapa, incluidos los intentos fallidos |
| `provenance.jsonl` | Registro crudo: cada version y cada etapa, con su fecha |
| `sast/*.sarif` | Salida original de Semgrep y de SpotBugs, sin tocar |
| `dast/zap.json` | Salida original de ZAP, sin tocar |
| `respuestas_zap.csv` | Las respuestas HTTP que provocaron los ataques de la etapa 6 |

Los ficheros `hallazgos_*.csv` intermedios muestran el estado tras cada etapa, de
forma que se puede ver que anade cada una.

---

## 4. Las cinco configuraciones que se comparan

| Config | Que es | Para que sirve |
|---|---|---|
| C0 | Cada herramienta por separado | Saber que aporta cada una sola |
| C1 | Semgrep + SpotBugs juntos | **La linea base a batir**: el SAST tradicional |
| C2 | Solo ZAP | Ver que consigue el analisis dinamico solo |
| C3 | Las tres juntas, sin filtrar | Comprobar si basta con juntarlo todo |
| C4 | C3 + confirmacion + clustering | **La propuesta del TFT** |

La pregunta del trabajo es si C4 tiene menos falsos positivos que C1 sin perder
demasiados aciertos.

---

## 5. Como compruebo que las cifras son reales

### 5.1. Mirar el resultado principal

```powershell
Import-Csv results\metrics.csv | Where-Object { $_.cwe -eq "TOTAL" } |
  Format-Table configuracion, TP, FP, FN, precision, recall, f1, benchmark_score
```

Significado de las columnas:

- **TP** (acierto): la herramienta avisa y el caso era vulnerable de verdad.
- **FP** (falso positivo): avisa y el caso **no** era vulnerable. Es lo que se quiere reducir.
- **FN**: no avisa y el caso si era vulnerable. Un fallo peligroso.
- **TN**: no avisa y no era vulnerable. Correcto.
- **precision**: de todo lo que avisa, cuanto es verdad.
- **recall**: de todo lo vulnerable, cuanto encuentra.
- **benchmark_score**: la nota oficial del OWASP Benchmark (recall menos tasa de falsa alarma).

Comprobacion rapida de coherencia: en cada fila, TP+FP+FN+TN debe dar
exactamente el numero de casos de esa categoria (2.740 en la fila TOTAL).

### 5.2. Rehacer la cuenta a mano

Esto recalcula los falsos positivos de C4 directamente desde los hallazgos, sin
fiarse de `metrics.csv`. Si el numero coincide, la tabla es correcta:

```powershell
# Casos que NO son vulnerables segun la solucion oficial
$noVulnerables = @{}
Get-Content external_benchmark_src\expectedresults-1.2.csv |
  Where-Object { $_ -notmatch "^#" } | ForEach-Object {
    $c = $_ -split ","
    if ($c[2] -eq "false") { $noVulnerables[$c[0]] = $c[3] }
  }

# Hallazgos que C4 conserva y que apuntan a un caso NO vulnerable de su categoria.
# Se cuentan pares unicos (caso, CWE) porque varios avisos sobre el mismo caso y
# el mismo tipo de fallo son el mismo falso positivo, no varios.
$fp = Import-Csv results\hallazgos.csv |
  Where-Object { $_.estado_final -ne "descartado" } |
  Where-Object { $noVulnerables[$_.caso] -eq $_.cwe } |
  Select-Object -Unique caso, cwe
"Falsos positivos de C4 contados a mano: $($fp.Count)"
```

Con los resultados actuales ese comando devuelve exactamente el mismo numero que
la columna FP de la fila C4 en `metrics.csv`. Si alguna vez no coincidieran,
la tabla seria sospechosa.

### 5.3. Seguir un hallazgo concreto de principio a fin

La comprobacion mas convincente: coger un caso y recorrerlo entero.

```powershell
$caso = "BenchmarkTest00008"

# 1. El codigo fuente original
Get-Content external_benchmark_src\src\main\java\org\owasp\benchmark\testcode\$caso.java

# 2. Que dice la solucion oficial sobre el (nombre, categoria, vulnerable, CWE)
Select-String -Path external_benchmark_src\expectedresults-1.2.csv -Pattern $caso

# 3. Que encontraron las herramientas y cual fue el veredicto
Import-Csv results\hallazgos.csv | Where-Object { $_.caso -eq $caso } |
  Format-Table herramienta, cwe, linea, ruta_http, parametro, vector, estado_final, evidencia_zap

# 4. Atacar esa URL manualmente y ver que responde la aplicacion
curl.exe -k "https://localhost:8443/benchmark/sqli-00/$caso"
```

Asi se ve el resultado de los pasos 2 y 3 con ese caso concreto:

```
BenchmarkTest00008,sqli,true,89          <- es vulnerable de verdad, inyeccion SQL

herramienta cwe linea ruta_http                             parametro          vector estado_final
semgrep     89  57    /benchmark/sqli-00/BenchmarkTest00008 BenchmarkTest00008 header confirmado
spotbugs    89  57    /benchmark/sqli-00/BenchmarkTest00008 BenchmarkTest00008 header confirmado
spotbugs    807 45    /benchmark/sqli-00/BenchmarkTest00008 BenchmarkTest00008 header no_verificable
zap         89        /benchmark/sqli-00/BenchmarkTest00008 BenchmarkTest00008 header observado_dast
```

Como leerlo: el caso es vulnerable de verdad (`true,89`). Los dos analizadores de
codigo lo detectan en la misma linea 57 del fuente y el ataque de ZAP lo
**confirma**, asi que cuenta como acierto. ZAP ademas lo encontro por su cuenta.
El aviso de CWE-807 de SpotBugs queda "no verificable" porque ese tipo de fallo no
esta entre los once que mide el Benchmark, y por eso no suma ni resta.

Fijate en la columna `vector`: este caso recibe la entrada por **cabecera HTTP**,
no por un parametro normal. Es un detalle importante del proyecto, porque un
tercio de los casos del Benchmark funcionan asi y ZAP no los ataca si no se le
configura expresamente para ello.

Si lo que dice el paso 3 encaja con lo que ves en los pasos 1, 2 y 4, el pipeline
esta diciendo la verdad sobre ese caso. Repitiendolo con unos pocos casos al azar
se gana confianza en el conjunto.

### 5.4. Contrastar las cifras con la herramienta oficial de OWASP

Esta es **la comprobacion mas fuerte de todas**, y la que conviene mirar primero
si solo se va a mirar una. Todo lo anterior comprueba que el proyecto es
coherente consigo mismo; esto comprueba que su forma de puntuar coincide con la
del propio proyecto OWASP Benchmark.

El Benchmark tiene su propia herramienta de puntuacion, **BenchmarkUtils**, que
es la que genera los scorecards que OWASP publica. Se le pueden pasar las salidas
originales de Semgrep, SpotBugs y ZAP y pedirle que puntue ella misma. Si sus
numeros coinciden con los de `metrics.csv`, entonces el codigo de evaluacion de
este proyecto no se ha inventado nada.

```powershell
docker compose run --rm orchestrator python run_all.py --stages validate
```

Tarda unos 2 minutos (8 mas la primera vez, porque hay que regenerar el informe
de SpotBugs en el formato XML que lee la herramienta oficial). Resultado:

```
  --- C0-spotbugs ---
  metrica              oficial       mio
  tp                      1375      1375
  fp                       640       640
  fn                        40        40
  tn                       685       685

  --- coincidencia caso a caso ---
  config          oficial      mio  solo of.  solo mio   igual
  C0-semgrep         1482     1482         0         0      si
  C0-spotbugs        2015     2015         0         0      si
  C0-zap              549      549         0         0      si

  recuentos TP/FP/FN/TN exactos: 12/12
  metricas coincidentes:         24/24
  motores identicos caso a caso: 3/3
```

Las dos cosas que verifica, y que conviene no confundir:

- **Por totales:** las 24 metricas (TP, FP, FN, TN, precision, recall, F1 y
  Benchmark Score de cada uno de los tres motores) coinciden.
- **Caso a caso:** los dos scorers marcan exactamente los mismos casos, ni uno
  mas ni uno menos. Esto es lo importante, porque dos recuentos iguales podrian
  en teoria salir de errores que se compensan entre si.

Solo se validan las configuraciones C0, es decir cada motor por separado. Las
uniones C1-C3 y la confirmacion cruzada C4 son la aportacion de este trabajo y no
existen en BenchmarkUtils, asi que no hay nada oficial contra lo que compararlas.
Lo que importa es que C1-C4 se calculan con el mismo codigo de evaluacion y sobre
los mismos hallazgos que C0: si C0 es correcto, el mecanismo tambien lo es.

Los scorecards HTML que produce la herramienta oficial quedan en
`results\scorecard_oficial\scorecard\` y se pueden abrir en el navegador:

```powershell
Invoke-Item results\scorecard_oficial\scorecard\Benchmark_v1.2_Scorecard_for_SBwFindSecBugs_v1.14.0.html
```

### 5.5. Comprobar las versiones y el entorno

```powershell
Get-Content results\entorno.txt
```

Ese fichero no declara ninguna version de memoria: cada una se le pregunto a la
herramienta durante la ejecucion y quedo registrada en `provenance.jsonl`. Para
verificar que el codigo analizado es el que se dice:

```powershell
# Debe coincidir con "commit" en configs\pipeline.yml
git -C external_benchmark_src rev-parse HEAD
Select-String -Path configs\pipeline.yml -Pattern "commit:"
```

---

## 6. Como repetirlo todo desde cero

```powershell
docker compose down
docker compose build
docker compose run --rm orchestrator python run_all.py --all
```

Tarda unas 5-6 horas. Para ejecutar solo una parte:

```powershell
docker compose run --rm orchestrator python run_all.py --list
docker compose run --rm orchestrator python run_all.py --stages deploy,sast
```

Los resultados del SAST son deterministas: Semgrep y SpotBugs dan exactamente los
mismos numeros en cada ejecucion. Los de ZAP varian ligeramente entre ejecuciones
porque un escaneo activo depende de tiempos de respuesta, asi que **no hay que
alarmarse si el total de alertas cambia en un 1-2%**.

---

## 7. Limitaciones que hay que conocer antes de leer los resultados

1. **ZAP solo puede comprobar 6 de los 11 tipos de fallo.** Tiene reglas para
   path traversal, inyeccion de comandos, XSS, inyeccion SQL, XPath y cookie
   insegura. No las tiene para inyeccion LDAP (esta en un complemento que no se
   instala) ni para cifrado debil, hash debil, aleatoriedad debil y violacion de
   limite de confianza, que son propiedades del codigo y no se ven en una
   respuesta HTTP. Los avisos de esos cinco tipos quedan como **no verificables y
   se conservan**: descartarlos seria castigar al hallazgo por una limitacion de
   la herramienta dinamica.
2. **El clustering no discrimina en XSS.** Como el ataque se refleja en la
   respuesta, esta siempre cambia respecto a la normal, asi que confirma tambien
   los falsos positivos. Se ve en `metrics.csv`: en CWE-79 los FP no bajan.
3. **El Benchmark no tiene ningun caso de CSRF**, asi que excluirlo no quita nada.
4. **Las herramientas no siempre usan el mismo numero de CWE** para lo mismo (por
   ejemplo 326 y 327 para cifrado debil). Las equivalencias aplicadas estan a la
   vista en `configs\pipeline.yml`, en `cwe_equivalences`.

---

## 8. Donde esta cada cosa en el codigo

```
configs\pipeline.yml   Toda la configuracion: versiones, rutas, reglas, equivalencias
run_all.py             Punto de entrada: ejecuta las etapas
src\deploy\            Etapa 1      src\verify\     Etapa 6
src\sast\              Etapa 2      src\cluster\    Etapa 7
src\dast\              Etapa 3      src\evaluate\   Etapa 8 y graficas
src\normalize\         Etapa 4      src\common\     Configuracion, registro y utilidades
src\mapping\           Etapa 5      src\validate\   Validacion con el scorer oficial (5.4)
```

Cada fichero de `src\` empieza con una explicacion de que hace esa etapa y por
que se tomo cada decision. Si algo del resultado no se entiende, esa cabecera es
el primer sitio donde mirar.
