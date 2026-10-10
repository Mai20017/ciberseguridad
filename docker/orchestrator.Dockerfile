# Contenedor orquestador: ejecuta run_all.py sobre Python 3.11 y lanza los
# contenedores hermanos (Semgrep, SpotBugs+FindSecBugs, ZAP) contra el demonio
# Docker del host mediante el socket montado.
FROM python:3.11.17-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

ENV TFT_IN_CONTAINER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MPLBACKEND=Agg

CMD ["python", "run_all.py", "--help"]
