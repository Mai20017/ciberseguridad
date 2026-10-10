# Etapa 1 del pipeline: despliegue del OWASP Benchmark v1.2.
#
# Replica lo que hace ./runBenchmark.sh del proyecto original
# (mvn initialize + mvn clean package cargo:run -Pdeploy) con tres ajustes:
#   1. runenv=remote: el server.xml del perfil "local" ata el conector a
#      127.0.0.1, con lo que el puerto no seria alcanzable ni desde el host
#      ni desde el contenedor de ZAP.
#   2. Tomcat se empaqueta dentro de la imagen y se referencia con file://,
#      para que el arranque no dependa de la red ni de que el mirror de Apache
#      siga publicando esta version concreta.
#   3. spotless:apply desactivado: necesita un repositorio git (que no se copia
#      a la imagen) y reformatearia el codigo fuente, con lo que los numeros de
#      linea de los hallazgos SAST dejarian de corresponder al commit analizado.
#
# JDK 17 es el que usa el CI del propio Benchmark (.github/workflows/maven.yaml)
# y es obligatorio: su .mvn/jvm.config pasa flags --add-exports que no existen
# en JDK 8. El bytecode generado sigue siendo Java 8 (java.target=8 en el pom).
FROM maven:3.9.16-eclipse-temurin-17

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /benchmark

ADD https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.122/bin/apache-tomcat-9.0.122.zip /opt/apache-tomcat-9.0.122.zip

COPY external_benchmark_src/ /benchmark/

# Dependencias y compilacion en tiempo de build: el arranque del contenedor solo
# tiene que empaquetar el war y levantar Tomcat.
RUN mvn -B -Dspotless.apply.skip=true initialize && mvn -B -Dspotless.apply.skip=true -DskipTests package

EXPOSE 8443

# La fase "package" se repite en cada arranque a proposito: el perfil deploy
# engancha ahi el arranque del servidor LDAP y de HSQLDB, que los casos de
# prueba del Benchmark necesitan en tiempo de ejecucion.
CMD ["mvn", "-B", "-Drunenv=remote", "-Dtomcat.url=file:///opt/apache-tomcat-9.0.122.zip", "-Dspotless.apply.skip=true", "-DskipTests", "package", "cargo:run", "-Pdeploy"]
