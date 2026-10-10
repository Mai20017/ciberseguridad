# De OWASP Benchmark a una aplicación web real: qué habría que cambiar

Documento de trabajo. Responde a una pregunta concreta: si el título promete
*automatizar la búsqueda de vulnerabilidades en una web*, ¿qué habría que cambiar
en el diseño actual para que eso fuera cierto, y qué dice la literatura revisada
al respecto?

Las referencias que se verifican a texto completo van marcadas con **[v]**. Las
que proceden de la síntesis temática propia (`Sintesis_Tematica_SLR.docx`,
basada en extracción con NotebookLM) van marcadas con **[s]** y **deben
comprobarse a texto completo antes de citarlas en la memoria**: el propio
documento de síntesis declara que es un corte preliminar.

---

## 1. El problema, en una frase

De las nueve etapas del sistema, **ocho son trasladables a cualquier aplicación
web y una no lo es**. La etapa 5 (mapeo de un hallazgo estático a su ruta HTTP y
su parámetro) depende de `benchmark-crawler-http.xml`, un fichero propio del banco
de pruebas que da ya resueltos la URL y el vector de entrada de cada caso, y de
identificar el caso por el nombre del fichero (`BenchmarkTestNNNNN`).

Una aplicación real no publica ese mapa. Sin él, el sistema sabe que hay un
hallazgo en `UserController.java:142` pero no sabe a qué URL hay que atacar para
comprobarlo, y la confirmación cruzada —que es el aporte del trabajo— no puede
ejecutarse.

Todo lo demás (desplegar, analizar, normalizar, escanear de forma dirigida,
comparar respuestas, evaluar, informar) es independiente del banco de pruebas.

---

## 2. Cómo resuelve la literatura ese mapeo

Hay tres vías en el corpus revisado, en orden de fuerza de la evidencia.

### 2.1. Un agente en el servidor: IAST con análisis de taint dinámico

Es la vía con mejor evidencia y la que resuelve el problema de raíz. Mateo Tudela
et al. (2020) **[v]** describen las herramientas IAST como herramientas de caja
blanca que

> «se basan en la ejecución de un agente en el lado del servidor. Este agente es
> responsable de monitorizar el comportamiento de la aplicación»

y señalan que

> «la correlación de datos entre herramientas SAST e IAST es normalmente más
> precisa, al ser ambas de caja blanca»,

y que las IAST «generan menos falsos positivos». Una de sus técnicas es
precisamente el análisis de taint dinámico.

Por qué esto resuelve la etapa 5: el agente observa, en tiempo de ejecución,
**qué petición HTTP concreta alcanza qué sumidero del código**. Es decir, produce
la correspondencia (ruta, parámetro) → (fichero, línea) por observación, no por
un fichero de configuración. Es exactamente el dato que hoy se lee del XML del
Benchmark.

Resultados de Mateo Tudela et al. **[v]**, sobre **el mismo OWASP Benchmark** que
usa este trabajo:

- las combinaciones que incluyen IAST obtienen los mejores resultados;
- IAST+DAST obtiene muy buenos resultados;
- las combinaciones con SAST son en general buenas «a pesar de tener una tasa de
  falsos positivos más alta que IAST y DAST», pero el SAST tiene «muy buena tasa
  de verdaderos positivos», así que debe incluirse.

Ese último punto coincide con lo medido en este trabajo: SpotBugs+FindSecBugs
alcanza exhaustividad 0,972 con precisión 0,682.

**Coste de adoptarlo:** las IAST del estudio son comerciales (Contrast Community
Edition, CxIAST). Hay opciones libres para Java, pero añadir un agente al
servidor es un cambio de arquitectura, no un parámetro.

### 2.2. Instrumentar los sumideros y comprobar si la petición los alcanza

Variante más ligera del mismo principio. Cefuzz (Zhao et al., 2022) **[s]** dirige
el fuzzing dinámico con las rutas de taint del análisis estático e **instrumenta
puntos de control en el código PHP** en lugar de comparar respuestas HTTP. Según
la síntesis, confirma 7 de 7 vulnerabilidades RCE reales.

CraftFuzz (Zhao et al., 2024) **[s]** va un paso más allá: resuelve dinámicamente
las restricciones necesarias para validar una alerta estática y genera una prueba
de concepto automática, confirmando 168 de 189 vulnerabilidades.

Por qué importa para este trabajo: ambos sustituyen la pregunta débil
*«¿cambió la respuesta?»* por la pregunta fuerte *«¿llegó la entrada al sumidero
y se ejecutó?»*. Eso elimina de golpe el problema que aquí no se ha podido
resolver en XSS reflejado, y no necesita ningún mapa del banco de pruebas.

### 2.3. Extraer los puntos de entrada del enrutado de la aplicación

La vía más barata y la única puramente estática. Song et al. (2023) **[s]**
extraen estáticamente los *endpoints* y después hacen fuzzing guiado por
aprendizaje por refuerzo.

En una aplicación Java moderna esto es viable: las anotaciones del framework
(`@RequestMapping`, `@GetMapping`, JAX-RS) declaran ruta y parámetros, y un
analizador puede construir el mapa que aquí se lee del XML. Es lo que se descartó
en su momento —véase la cabecera de `src/mapping/sast_to_http.py`— porque las
anotaciones `@WebServlet` del Benchmark **no indican el vector de entrada**
(parámetro GET, formulario, cabecera o cookia), dato que la etapa 6 necesita. En
un framework moderno sí se declara, así que la objeción desaparece.

**Es la vía recomendable para un trabajo de máster**: no requiere agente, no
requiere herramienta comercial, y es acotable a un framework concreto.

---

## 3. El cambio más importante: la línea base está mal construida

Esto no es una cuestión de aplicación real o sintética. Es un error de fidelidad
al artículo que sostiene todo el marco conceptual, y conviene corregirlo en
cualquier caso.

### Qué hace Akrout et al. (2014) **[v]**

Su método (Wasapy) **no compara la respuesta al ataque con la respuesta normal**.
Define **tres conjuntos de peticiones**:

| Conjunto | Qué es | Respuestas |
|---|---|---|
| `Rr` | Peticiones con palabras **aleatorias** de `[a-zA-Z0-9]+` | `Sr` |
| `Rii` | Inyecciones **sintácticamente inválidas** | `Sii` |
| `Rvi` | Inyecciones **válidas** (el ataque de verdad) | `Svi` |

Y la regla de decisión es:

> «Las peticiones `Rvi` cuyas respuestas no son similares a ninguna de las
> respuestas de `Sii` y `Sr` se consideran inyecciones SQL válidas.»

La distancia es una **Levenshtein normalizada**, y los supuestos declarados son
que una página de ejecución difiere significativamente de una de rechazo, que dos
páginas de rechazo pueden diferir entre sí, y que dos de ejecución también.

Los autores justifican expresamente por qué parten de peticiones que fallan:

> «es más fácil generar peticiones aleatorias o sintácticamente inválidas para
> obtener páginas de rechazo que enviar ataques de inyección válidos.»

### Qué hace la implementación actual de este trabajo

Una sola línea base: la respuesta a la **entrada válida** del rastreador. Un único
punto de referencia, y la regla es «¿se separa algo de él?».

### Por qué la diferencia lo explica casi todo

1. **Explica el fracaso en XSS.** Con la referencia en el comportamiento normal,
   cualquier *payload* que altere la salida se separa, **aunque la aplicación lo
   haya saneado**. En XSS reflejado el ataque se refleja por definición, así que
   se confirma todo, incluidos los falsos positivos.
2. **Explica por qué DBSCAN no aporta nada.** Está medido: 30 combinaciones de
   `eps` y `min_samples` dan resultados idénticos entre sí e idénticos a una regla
   trivial de invariancia. Con **una sola** muestra de referencia no hay
   estructura de densidad que agrupar; el algoritmo degenera en «¿hay algo
   distinto?». Con dos clases de respuestas de fallo (`Sr` y `Sii`), cada una con
   varias muestras, **sí** hay estructura, y el agrupamiento pasa a tener sentido.
3. **No necesita ningún mapa de código.** El método de Akrout es de caja negra
   pura. Para la pregunta «¿cómo se automatiza esto en una web real?», esta parte
   ya es trasladable tal cual.

### Qué habría que implementar

Por cada ruta y parámetro inyectable:

1. enviar N peticiones con valores aleatorios → recoger `Sr`;
2. enviar N peticiones con inyecciones malformadas → recoger `Sii`;
3. lanzar el escaneo activo dirigido de ZAP → recoger `Svi` (ya se hace);
4. confirmar solo si la respuesta de `Svi` no se parece a ninguna de `Sr ∪ Sii`.

**Tensión que hay que declarar:** generar `Rr` y `Rii` significa que el sistema
produce parte de las peticiones, lo que se aparta de la regla «las pruebas las
genera ZAP». Matiz importante: los **ataques** (`Rvi`) seguirían siendo de ZAP;
lo generado serían las peticiones que deben fallar, que Akrout obtiene «de una
gramática» y que no son *exploits*. Es defendible, pero hay que decirlo.

---

## 4. El otro cambio: verificar XSS en el DOM, no en la respuesta

Song et al. (2023) **[s]** validan «la ejecución real del *payload* XSS en el DOM»
usando un navegador sin interfaz. Es la respuesta correcta al problema de XSS:
la pregunta no es si la respuesta cambió, sino si el script **se ejecutó**.

Implementarlo requiere añadir un navegador controlado al pipeline. Es un cambio
acotado y resolvería la limitación más visible del filtro actual.

---

## 5. Dónde validarlo si se quiere hablar de «una web»

El corpus propio ya señala los objetivos habituales:

- **OWASP Juice Shop** y **NodeGoat**, usados por Abdulghaffar et al. (2023)
  **[s]**, que además obtienen 100 % de precisión por intersección de dos DAST a
  costa de exhaustividad. Ese resultado es el mismo patrón que aquí se ha medido
  en la ablación C4a (solo alerta de ZAP): más precisión, menos exhaustividad.
- **Plugins reales de WordPress**, usados por Bermejo Higuera et al. (2021)
  **[s]**, cuyo hallazgo —que combinar 2 o 3 herramientas SAST maximiza la
  precisión y que añadir más **no** mejora— coincide con lo medido aquí: la unión
  SAST (C1) empeora el F1 frente a SpotBugs solo (0,789 frente a 0,802).
- **Aplicaciones en producción**, como en Correa et al. (2021) **[s]**: SAST
  (Fortify) auditado dinámicamente con ZAP más verificación manual, 403 hallazgos
  → 43 falsos positivos descartados, 89,33 % de precisión. Es el trabajo más
  parecido a este, pero con humano en el bucle.

Validar en **una sola** aplicación adicional, aunque sea Juice Shop, cambia
cualitativamente el alcance de las conclusiones.

---

## 6. Cómo replantear la aportación con la literatura a favor

Hay dos frases en el corpus que sostienen la contribución mucho mejor que
«el clustering reduce falsos positivos», que es justo lo que los datos de este
trabajo no respaldan.

**La primera es el trabajo futuro de Mateo Tudela et al. (2020) [v]**, en el mismo
banco de pruebas:

> «La correlación de resultados entre herramientas de distinto tipo es todavía un
> aspecto poco extendido. Es necesario desarrollar una metodología o un software
> hecho a medida que permita, de forma automática o semiautomática, la evaluación
> y correlación de los resultados obtenidos por varias herramientas de distinto
> tipo.»

El pipeline de este trabajo **es ese software**, sobre esa misma aplicación, y con
las métricas contrastadas caso por caso con el puntuador oficial de OWASP. Esa es
una aportación verificable y acotada.

**La segunda es Yulianton et al. (2020) [v]**, cuyo marco propuesto es,
esencialmente, la arquitectura de este trabajo: análisis de taint estático y
dinámico que produce «una lista de entradas de la aplicación sospechosas de
contener vulnerabilidades», sobre la que después se hace *black-box testing*. Pero
es un **modelo conceptual sin medición**: el propio artículo no aporta cifras de
falsos positivos.

Es decir: este trabajo es la **primera evaluación empírica, reproducible y
validada contra el puntuador oficial, del modelo que Yulianton et al. propusieron
sin medir**, y la respuesta parcial a la llamada explícita de Mateo Tudela et al.
Eso se defiende. Y el resultado negativo sobre el agrupamiento —medido, con
ablaciones y barrida de parámetros— es un hallazgo publicable en sí mismo, porque
el corpus propio identifica el clustering de respuestas HTTP como un hueco
abierto desde Akrout (2014) y Patil (2016), este último **nunca implementado por
nadie**.

---

## 7. Resumen de decisiones

| Cambio | Coste | Qué arregla | ¿Imprescindible? |
|---|---|---|---|
| Línea base de Akrout (`Rr`, `Rii`, `Rvi`) | ~1 día + 5 h de ejecución | Fidelidad al marco teórico, XSS, da sentido a DBSCAN | **Sí**, si se mantiene el marco de Akrout |
| Mapeo por anotaciones del framework | 2–3 días | La dependencia del banco de pruebas | Solo si el título promete «una web» |
| Verificación de XSS en el DOM | 2–3 días | El fracaso del filtro en XSS | No, pero es la limitación más visible |
| Agente IAST | Cambio de arquitectura | El mapeo, de raíz | No para un TFM |
| Validar en Juice Shop | 1–2 días | La validez externa | Muy recomendable |

**Sobre el título.** Si se mantiene «Automatización de la búsqueda de
vulnerabilidades en una web», hay que hacer al menos el mapeo por anotaciones y
validar en una aplicación que no sea el Benchmark; en caso contrario el título
promete una generalidad que el experimento no respalda. Si no se van a hacer esos
cambios, el título debe acotar el alcance, por ejemplo:

> Confirmación dinámica de hallazgos estáticos para la reducción de falsos
> positivos en aplicaciones web: evaluación sobre OWASP Benchmark v1.2

---

## 8. Advertencia sobre las citas

Las referencias marcadas **[s]** proceden de la síntesis temática propia, que se
construyó con extracción asistida y que el propio documento declara preliminar
(30 estudios únicos de 351 cribados; ~100 de prioridad alta sin procesar). Antes
de citar cualquiera de ellas en la memoria hay que verificarla a texto completo.
Las marcadas **[v]** se han comprobado directamente sobre el PDF.
