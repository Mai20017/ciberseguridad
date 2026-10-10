# Crawler oficial del OWASP Benchmark (etapa 3).
#
# El crawler vive en un repositorio aparte (BenchmarkUtils) que no esta
# declarado en el pom del Benchmark: hay que clonarlo e instalarlo en el repo
# Maven local. Se fija por commit, igual que el Benchmark, para que la
# ejecucion sea repetible.
#
# Se parte de la imagen del Benchmark para reutilizar sus fuentes y su cache de
# dependencias Maven ya descargada.
FROM tft-benchmark:1.2

ARG BENCHMARK_UTILS_COMMIT=ef982a71c377dd43d58652a450bf25fb7a8582ad

RUN git clone https://github.com/OWASP-Benchmark/BenchmarkUtils.git /tmp/benchmarkutils \
    && git -C /tmp/benchmarkutils checkout -q "${BENCHMARK_UTILS_COMMIT}" \
    && mvn -B -f /tmp/benchmarkutils/pom.xml -DskipTests -Dspotless.apply.skip=true install \
    && rm -rf /tmp/benchmarkutils

WORKDIR /benchmark
COPY docker/crawl.sh /usr/local/bin/crawl.sh
RUN chmod +x /usr/local/bin/crawl.sh
