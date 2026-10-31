# Guía paso a paso — Práctica 5: Snyk CLI

> ⚠️ Esta app es **intencionalmente vulnerable**. Ejecútala solo en tu Kali, en `127.0.0.1`.
> Si el docente te entregó su propio proyecto de laboratorio, úsalo a él como objetivo y usa
> este como guía de qué hacer en cada fase.

## Qué hay en la carpeta

| Archivo | Para qué sirve |
|---|---|
| `app.js` | La app vulnerable (ANTES). Tiene SQLi, XSS, inyección de comandos y un secreto quemado. |
| `package.json` | Dependencias vulnerables: `lodash 4.17.20` y `express 4.17.1`. |
| `remediacion/` | La versión corregida (DESPUÉS): `app.js`, `lib/seguridad.js`, `package.json`. |
| `test/funcional.test.js` | Prueba que la app funciona (debe pasar antes y después). |
| `test/seguridad.test.js` | Prueba los ataques (falla ANTES, pasa DESPUÉS). |
| `recolectar_evidencias.sh` | Corre todos los comandos Snyk y guarda las salidas en `evidencias/`. |
| `aplicar_remediacion.sh` | Copia la versión corregida y reinstala dependencias seguras. |
| `.githooks/pre-commit`, `.semgrep.yml`, `eslint.config.js`, `.cursorrules`, `.github/` | Controles Shift-Left. |
| `SECURITY_LAB_REPORT.md` | Plantilla del entregable, ya con el análisis técnico. |

---

## Fase 0 — Preparar Kali (una sola vez)

```bash
sudo apt update
sudo apt install -y nodejs npm git build-essential python3
node -v      # necesitas 18 o más (ideal 22)
```

`build-essential` y `python3` solo se usan si `sqlite3` no trae binario listo para tu equipo.

## Fase 1 — Instalar y autenticar Snyk

```bash
sudo npm install -g snyk          # opción A (con npm)
snyk --version                    # 📸 captura
snyk auth                         # abre el navegador → inicia sesión → "Authenticate"
snyk whoami --experimental        # 📸 captura (TAPA tu correo/usuario antes de entregar)
```

> En las versiones actuales del CLI, `whoami` exige la bandera `--experimental`.
> Si el docente pidió `SNYK_TOKEN`: `export SNYK_TOKEN=xxxx` (nunca lo escribas en archivos del repo).

**Activa Snyk Code** (si no, `snyk code test` no funciona): en app.snyk.io →
**Settings → Snyk Code → Enable Snyk Code → Save changes**.

## Fase 2 — Preparar el proyecto y guardar el "ANTES"

```bash
cd snyk-lab
npm install
git init
git add .
git commit -m "Estado inicial vulnerable (ANTES)"
```

Registra el entorno (pide el punto 5 de la Fase 1 de la guía):

```bash
uname -a; cat /etc/os-release | head -2; node -v; npm -v; snyk --version
```

## Fase 3 — Probar la app y la explotación controlada (solo localhost)

Terminal 1:
```bash
npm start            # "Snyk Lab (VULNERABLE) en http://127.0.0.1:3000"
```

Terminal 2 (📸 una captura por comando):
```bash
# Uso normal
curl -s -X POST http://127.0.0.1:3000/login -H "Content-Type: application/json" \
     -d '{"username":"ana","password":"Ana#2026"}'

# V1 - Inyección SQL: entrar como admin SIN contraseña
curl -s -X POST http://127.0.0.1:3000/login -H "Content-Type: application/json" \
     -d "{\"username\":\"admin'--\",\"password\":\"x\"}"

# V1 - Inyección SQL: volcar toda la tabla
curl -s "http://127.0.0.1:3000/users?name='%20OR%20'1'='1"

# XSS reflejado (ábrelo también en Firefox para ver la alerta)
curl -s "http://127.0.0.1:3000/search?q=<script>alert('XSS')</script>"

# V3 - Inyección de comandos: ejecuta "id" en el servidor
curl -s "http://127.0.0.1:3000/ping?host=127.0.0.1;id"
```

Detén la app con `Ctrl+C` y corre las pruebas:

```bash
npm test     # 📸 Esperado: 5 pasan (funcionales) y 4 fallan (seguridad) → las vulnerabilidades existen
```

## Fase 4 — Escaneos Snyk (ANTES)

```bash
./recolectar_evidencias.sh antes
```

Esto ejecuta `snyk test`, `snyk test --severity-threshold=high`, `snyk code test` y `npm ls`,
y guarda todo en `evidencias/antes/`. 📸 Toma captura de la terminal de cada escaneo.

> `snyk monitor` solo si el docente lo pide: sube un "snapshot" del proyecto a tu cuenta.

## Fase 5 — Elegir las 3 vulnerabilidades (sugerencia)

| # | Hallazgo | Tipo | Dónde |
|---|---|---|---|
| 1 | Inyección SQL | SAST | `app.js` líneas 45–51 y 63–65 |
| 2 | lodash 4.17.20 (CVE-2021-23337 y otros) | SCA | `package.json` (dependencia directa) |
| 3 | Inyección de comandos | SAST | `app.js` línea 86 |

Alternativas si Snyk no reporta alguno: XSS (`app.js` línea 77), secreto quemado (línea 19),
o una dependencia **transitiva** de express 4.17.1 (por ejemplo `qs`, `path-to-regexp`, `body-parser`).
Usa SIEMPRE los datos exactos que te muestre Snyk (severidad, línea, CVE, versión de arreglo).

## Fase 6 — Remediar

```bash
./aplicar_remediacion.sh          # copia el código corregido, reinstala y corre npm test
git diff > evidencias/diff_remediacion.txt
git diff --stat                   # 📸 captura
git add . && git commit -m "Remediación: SQLi, XSS, command injection, secreto y dependencias"
```

📸 `npm test` ahora debe mostrar **9 de 9 pruebas pasando**: la app funciona y los ataques fallan.
Repite los `curl` de la Fase 3 (con `npm start`) para ver las respuestas `400` / `401`.

## Fase 7 — Verificar (reescaneo obligatorio)

```bash
./recolectar_evidencias.sh despues
```

Compara `evidencias/antes/` con `evidencias/despues/`. Si queda algún hallazgo (por ejemplo una
dependencia transitiva de `sqlite3` sin versión corregida), **no lo ocultes**: explícalo en el
informe (por qué permanece y qué mitigación hay).

## Fase 8 — Shift-Left (prevención)

```bash
git config core.hooksPath .githooks     # activa el pre-commit
pipx install semgrep                    # o: pip install semgrep
semgrep --config .semgrep.yml .         # 📸 sobre el código corregido no debe reportar errores
npm run lint                            # ESLint + plugin de seguridad
```

**Demostración del bloqueo** (📸): vuelve a meter una línea vulnerable a propósito y trata de hacer commit:

```bash
echo 'const API_TOKEN = "abc123456789";' >> app.js
git add app.js && git commit -m "prueba"     # el hook debe BLOQUEAR el commit
git checkout app.js                           # deshace el cambio
```

**Quality Gate en CI/CD** (opcional pero suma): sube el repo a GitHub, crea el secreto `SNYK_TOKEN`
(Settings → Secrets and variables → Actions) y el workflow `.github/workflows/security.yml` correrá
en cada Pull Request. Para **bloquear PRs**: Settings → Branches → regla para `main` →
"Require status checks to pass" → marca los jobs del workflow.

## Fase 9 — Informe

Completa `SECURITY_LAB_REPORT.md`: reemplaza cada `[PEGAR ...]` con tus salidas y capturas,
y revisa que los números (severidad, CVSS, líneas) coincidan con lo que **tu** Snyk reportó.
