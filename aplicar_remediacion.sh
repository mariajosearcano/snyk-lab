#!/usr/bin/env bash
# Aplica la versión corregida sobre el proyecto (para generar el "DESPUÉS").
# Úsalo SOLO después de haber hecho el escaneo inicial y el commit "antes".
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/4] Copiando código corregido..."
mkdir -p lib
cp remediacion/lib/seguridad.js lib/seguridad.js
cp remediacion/app.js app.js
cp remediacion/package.json package.json

echo "[2/4] Reinstalando dependencias con versiones seguras..."
rm -rf node_modules package-lock.json
npm install

echo "[3/4] Pruebas funcionales y de seguridad..."
npm test

echo "[4/4] Listo. Ahora ejecuta:  git diff  |  snyk test  |  snyk code test"
