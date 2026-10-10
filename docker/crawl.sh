#!/bin/sh
# Ejecuta el crawler oficial del Benchmark a traves del proxy de ZAP.
#
# ZAP intercepta el trafico TLS presentando certificados firmados por su propia
# CA raiz, que la JVM no conoce. Esa CA se genera por instancia de ZAP, asi que
# hay que importarla en tiempo de ejecucion (no sirve hacerlo al construir la
# imagen) en una copia del almacen de confianza del JDK.
set -e

ZAP_HOST="${ZAP_HOST:-zap}"
ZAP_PORT="${ZAP_PORT:-8090}"
CRAWLER_FILE="${CRAWLER_FILE:-/out/benchmark-crawler-internal.xml}"

echo "Obteniendo la CA raiz de ZAP desde ${ZAP_HOST}:${ZAP_PORT}"
curl -fsS "http://${ZAP_HOST}:${ZAP_PORT}/OTHER/core/other/rootcert/?apikey=${ZAP_API_KEY}" \
    -o /tmp/zap-root.cer

cp "${JAVA_HOME}/lib/security/cacerts" /tmp/cacerts
chmod u+w /tmp/cacerts
keytool -importcert -noprompt -trustcacerts \
    -alias zap-root -file /tmp/zap-root.cer \
    -keystore /tmp/cacerts -storepass changeit > /dev/null

export MAVEN_OPTS="-Djavax.net.ssl.trustStore=/tmp/cacerts -Djavax.net.ssl.trustStorePassword=changeit"

echo "Lanzando el crawler oficial (benchmarkutils run-crawler)"
exec mvn -B org.owasp:benchmarkutils-maven-plugin:run-crawler \
    -DcrawlerFile="${CRAWLER_FILE}" \
    -DproxyHost="${ZAP_HOST}" \
    -DproxyPort="${ZAP_PORT}"
