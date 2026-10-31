#!/usr/bin/env bash
# Ejecuta los análisis de Snyk y guarda TODO en la carpeta evidencias/
# Uso:  ./recolectar_evidencias.sh antes     (o)     ./recolectar_evidencias.sh despues
set -uo pipefail
cd "$(dirname "$0")"
ETAPA="${1:-antes}"
DIR="evidencias/$ETAPA"
mkdir -p "$DIR"

echo "== Entorno ==" | tee "$DIR/00_entorno.txt"
{ uname -a; cat /etc/os-release 2>/dev/null | head -2; echo "node $(node -v)"; echo "npm $(npm -v)"; echo "snyk $(snyk --version)"; date; } | tee -a "$DIR/00_entorno.txt"

echo; echo "== SCA: snyk test =="
snyk test | tee "$DIR/01_snyk_test.txt"
snyk test --json > "$DIR/01_snyk_test.json"

echo; echo "== SCA: snyk test --severity-threshold=high =="
snyk test --severity-threshold=high | tee "$DIR/02_snyk_test_high.txt"

echo; echo "== SAST: snyk code test =="
snyk code test | tee "$DIR/03_snyk_code_test.txt"
snyk code test --json > "$DIR/03_snyk_code_test.json"

echo; echo "== Árbol de dependencias (directa vs transitiva) =="
npm ls --all > "$DIR/04_npm_ls.txt" 2>&1
npm ls lodash express | tee "$DIR/04_npm_ls_resumen.txt"

echo; echo "Evidencias guardadas en $DIR"
echo "Nota: snyk devuelve código de salida 1 cuando encuentra vulnerabilidades; eso es normal."
