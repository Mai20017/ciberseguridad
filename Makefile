# Pipeline SAST+DAST sobre OWASP Benchmark v1.2
#
# Todo se ejecuta en contenedores. El fichero .env fija TFT_HOST_PROJECT_DIR,
# que el orquestador necesita para montar rutas del host en los contenedores
# hermanos (Semgrep, SpotBugs, ZAP).
#
# En Windows sin make, usa directamente los comandos "docker compose" que
# aparecen en cada receta (estan documentados en el README).

ORCH := docker compose run --rm orchestrator python run_all.py

.PHONY: help env build deploy sast dast all stages down clean logs-benchmark logs-zap freeze

help:
	@echo "make env              Genera .env con la ruta del proyecto en el host"
	@echo "make build            Construye las imagenes (Benchmark + orquestador)"
	@echo "make deploy           Etapa 1: despliega el Benchmark y espera a que responda"
	@echo "make sast             Etapa 2: Semgrep + SpotBugs/FindSecBugs (SARIF)"
	@echo "make all              Ejecuta todas las etapas implementadas"
	@echo "make stages           Lista las etapas disponibles"
	@echo "make down             Para y elimina los contenedores"
	@echo "make logs-benchmark   Sigue los logs de Tomcat"

env:
	@printf 'TFT_HOST_PROJECT_DIR=%s\n' "$$(pwd -W 2>/dev/null || pwd)" > .env
	@cat .env

build:
	docker compose build

deploy:
	$(ORCH) --stages deploy

sast:
	$(ORCH) --stages sast

dast:
	$(ORCH) --stages dast

all:
	$(ORCH) --all

stages:
	$(ORCH) --list

down:
	docker compose down

logs-benchmark:
	docker compose logs -f benchmark

logs-zap:
	docker compose logs -f zap

# Regenera requirements.txt con el bloqueo exacto de versiones instaladas
freeze:
	docker compose run --rm --entrypoint sh orchestrator -c "pip freeze" > requirements.txt
	@echo "requirements.txt actualizado"
