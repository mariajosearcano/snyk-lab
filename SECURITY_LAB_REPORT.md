# SECURITY_LAB_REPORT — Auditoría AppSec con Snyk CLI

> Plantilla con el análisis técnico ya redactado. Reemplaza todo lo que diga **[PEGAR ...]** o
> **[COMPLETAR]** con TUS salidas reales. Si Snyk te muestra un dato distinto (severidad, línea,
> versión de arreglo), **manda lo que diga Snyk** y ajusta el texto.

## 1. Portada técnica

| Campo | Valor |
|---|---|
| Auditor(a) | María José Arcila Cano — Documento: [COMPLETAR] |
| Programa | Diplomado en Ciberseguridad Informática y Resiliencia Digital — Politécnico Colombiano JIC |
| Docente | Edwin Andrés Ochoa Agudelo |
| Grupo / Semestre | [COMPLETAR] / 2026_02 |
| Repositorio | `snyk-lab-tienda` (local) — [URL de GitHub si lo subiste] |
| Fecha | [COMPLETAR] |
| Entorno | [PEGAR salida de `evidencias/antes/00_entorno.txt`: SO, Node, npm, versión Snyk CLI] |
| Lenguaje / framework | JavaScript (Node.js) / Express + SQLite |

## 2. Resumen ejecutivo

Se auditó una aplicación web Node.js de laboratorio con Snyk CLI combinando **SCA** (análisis de
dependencias, `snyk test`) y **SAST** (análisis de código propio, `snyk code test`). Se seleccionaron
tres hallazgos: una **inyección SQL** que permite iniciar sesión como administrador sin contraseña,
una **dependencia vulnerable (lodash 4.17.20)** y una **inyección de comandos del sistema operativo**
que permite ejecutar órdenes en el servidor. Los tres se corrigieron atacando la causa raíz
(consultas parametrizadas, actualización de la dependencia y ejecución sin shell con lista blanca),
se comprobó que la aplicación sigue funcionando (pruebas funcionales 5/5) y que los ataques ya no
funcionan (pruebas de seguridad 4/4), y se verificó con un reescaneo de Snyk. Finalmente se
implementaron controles Shift-Left: reglas para el asistente de IA, ESLint y Semgrep, hook pre-commit
con detección de secretos y un Quality Gate en GitHub Actions que bloquea PR con severidad alta o crítica.

**Riesgo más alto:** la inyección de comandos (V3), porque es explotable sin autenticación y da
control del servidor. [Ajustar si tu análisis concluye otra cosa.]

## 3. Metodología y alcance

- **Alcance:** solo el proyecto local `snyk-lab-tienda`, ejecutado en `127.0.0.1`. No se escanearon
  ni atacaron sistemas de terceros.
- **Ciclo aplicado:** detección → análisis → priorización → remediación → verificación → prevención.
- **Herramientas:** Snyk CLI (`snyk test`, `snyk test --severity-threshold=high`, `snyk code test`),
  `npm ls`, `curl`, `node --test`, ESLint + eslint-plugin-security, Semgrep, Git.
- **Criterio de priorización:** no solo CVSS; también explotabilidad (¿requiere login?, ¿hay exploit
  público?), alcance real (*reachability*: ¿el código vulnerable se ejecuta en nuestra app?) e impacto
  en el negocio.
- **Manejo de secretos:** el token de Snyk se manejó con `snyk auth` / variable de entorno; nunca se
  incluyó en el repositorio. Las capturas de `snyk whoami` se entregan con datos tapados.

## 4. Matriz de vulnerabilidades

| # | Hallazgo | SAST/SCA | CVE/CWE | Severidad (Snyk) | CVSS v3.1 | Riesgo real | Estado |
|---|---|---|---|---|---|---|---|
| 1 | Inyección SQL en `/login` y `/users` | SAST | CWE-89 | [PEGAR] | 8.2 (estimado*) | **Alto**: sin login, permite suplantar al admin y leer la tabla | Corregido |
| 2 | lodash 4.17.20 (dependencia directa) | SCA | CVE-2021-23337 (CWE-94); CVE-2020-28500 (CWE-1333) [+ otros que liste Snyk] | [PEGAR] | 7.2 / 5.3 | **Medio**: la función crítica `_.template` no se usa; `_.trim` sí recibe datos del usuario | Corregido |
| 3 | Inyección de comandos en `/ping` | SAST | CWE-78 | [PEGAR] | 9.8 (estimado*) | **Crítico**: ejecución remota de comandos sin autenticación | Corregido |

\* Snyk Code no publica CVSS para hallazgos de código propio; el puntaje lo calculó la auditora con la
calculadora CVSS v3.1 según el contexto de esta app (vector en cada ficha).

---

## 5. Vulnerabilidad 1 — Inyección SQL (SAST)

### 5.1 Ficha técnica y puntuación
- **Nombre:** SQL Injection.  **Tipo:** SAST.  **CWE:** CWE-89.  **OWASP:** A05:2025 – Injection.
- **Severidad reportada por Snyk:** [PEGAR].
- **CVSS v3.1 (estimado):** 8.2 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`.
- **Ubicación:** `app.js`, líneas 45–51 (`POST /login`) y 63–65 (`GET /users`).
- [PEGAR captura del hallazgo en `snyk code test`]

### 5.2 Interpretación del riesgo
- **Vector:** red (AV:N), baja complejidad (AC:L), **sin privilegios** (PR:N), sin interacción (UI:N).
- **CID:** Confidencialidad **alta** (se lee toda la tabla de usuarios, incluidas contraseñas);
  Integridad **baja** (se suplanta al admin, pero `db.get` no permite consultas apiladas);
  Disponibilidad **ninguna**.
- **Activo expuesto:** base de datos de usuarios y el mecanismo de autenticación.
- **Condiciones:** solo acceso HTTP al endpoint. **Exploit:** técnica pública y trivial (`admin'--`).
- **Reachability:** total — el dato del usuario llega directo a la consulta.
- **Impacto empresarial:** robo de cuentas, acceso administrativo no autorizado, fuga de datos
  personales (incumplimiento de la Ley 1581 de 2012), daño reputacional.

### 5.3 Causa raíz
Defecto de **implementación**: la consulta se arma **concatenando texto** con la entrada del usuario,
así que los caracteres `'` y `--` cambian la lógica del SQL (el dato se vuelve código).

```js
// ANTES - app.js líneas 45-51
const query =
  "SELECT id, username, role FROM users WHERE username = '" + username +
  "' AND password = '" + password + "'";
db.get(query, (err, row) => { ... });
```

### 5.4 Escenario de explotación controlada (localhost)
Con `username = admin'--` la consulta queda
`... WHERE username = 'admin'--' AND password = 'x'`; el `--` comenta la verificación de la clave y
se entra como **admin sin contraseña**. Con `name = ' OR '1'='1` en `/users` se obtienen todos los registros.
[PEGAR captura de los `curl` de la Fase 3 y de la prueba `SQLi` fallando en `npm test`]

### 5.5 Remediación
**Estrategia:** consultas **parametrizadas** (`?` + arreglo de valores): el motor recibe el SQL y los
datos por separado, por lo que la entrada nunca se interpreta como código. Defensa adicional: validación
de formato del usuario con lista blanca y mensajes de error genéricos.

```js
// DESPUÉS - app.js (corregido)
if (!usuarioValido(username) || typeof password !== "string") {
  return res.status(400).json({ ok: false, mensaje: "Entrada inválida" });
}
const query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
db.get(query, [username, password], (err, row) => { ... });
```

**Por qué corrige la causa raíz:** elimina la mezcla de código y datos (no depende de "filtrar" comillas).
**Funcionalidad:** pruebas funcionales 5/5 en verde (login válido sigue funcionando). [PEGAR captura]

### 5.6 Verificación
[PEGAR `snyk code test` DESPUÉS mostrando que el hallazgo CWE-89 desapareció] y prueba de seguridad `SQLi` en verde.

### 5.7 Prevención / Shift-Left
Regla Semgrep `sqli-entrada-usuario` (modo taint), regla 1 de `.cursorrules`, `snyk code test` en el
pre-commit y en el Quality Gate de CI.

---

## 6. Vulnerabilidad 2 — lodash 4.17.20 (SCA)

### 6.1 Ficha técnica y puntuación
- **Paquete:** `lodash@4.17.20` — **dependencia directa** (declarada en `package.json`).
- **Hallazgos principales:**
  - **CVE-2021-23337** — Command Injection en `_.template`. CVSS 3.1: **7.2 (Alta)** —
    `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`. Corregido en **4.17.21**.
  - **CVE-2020-28500** — ReDoS en `toNumber`, `trim`, `trimEnd`. CVSS 3.1: **5.3 (Media)** —
    `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`. Corregido en **4.17.21**.
  - [Si Snyk lo lista] **CVE-2025-13465** — Prototype Pollution en `_.unset`/`_.omit`.
    Afecta hasta 4.17.22; corregido en **4.17.23**.
- **Severidad reportada por Snyk:** [PEGAR].  **Versión segura aplicada:** `^4.17.23` (instalada: [PEGAR `npm ls lodash`]).
- **OWASP:** A03:2025 – Software Supply Chain Failures.
- [PEGAR captura de `snyk test` con lodash]

### 6.2 Interpretación del riesgo (aquí está la diferencia entre CVSS y riesgo real)
- **CVE-2021-23337 (7.2):** requiere privilegios altos (PR:H) y, sobre todo, que la app use
  `_.template` con opciones controladas por un atacante. **Esta app no usa `_.template`** → **no
  alcanzable** (*not reachable*). Riesgo real **bajo** aunque el CVSS sea "alto".
- **CVE-2020-28500 (5.3):** la app **sí** llama `_.trim(req.query.name)` en `/users` → la función
  vulnerable **sí es alcanzable** con datos del usuario y sin autenticación. Impacto: solo
  **Disponibilidad** (una cadena maliciosa puede ralentizar el servidor).
- **CID global:** C y I bajos en este contexto; A media.
- **Impacto empresarial:** caída o lentitud del servicio; además, dejar una dependencia desactualizada
  acumula deuda: cualquier uso futuro de `_.template` volvería explotable el CVE crítico.
- **Madurez del exploit:** [PEGAR lo que Snyk indique en "Exploit maturity", p. ej. Proof of Concept].

### 6.3 Causa raíz
Defecto de **dependencia/configuración**: versión fijada (`"lodash": "4.17.20"`) sin política de
actualización ni escaneo SCA en el flujo de desarrollo.

### 6.4 Escenario de explotación controlada
Un atacante envía a `/users?name=` una cadena muy larga de espacios/caracteres diseñada para que la
expresión regular interna de `trim` tarde muchísimo (ReDoS), ocupando el hilo único de Node.js y
dejando la app sin responder para otros usuarios. *(No se ejecutó la carga en el laboratorio para no
afectar el equipo; basta con demostrar alcance y versión vulnerable.)*

### 6.5 Remediación
```diff
- "lodash": "4.17.20",
+ "lodash": "^4.17.23",
```
Se reinstalaron dependencias (`npm install`) y se corrieron las pruebas: la app funciona igual
(lodash mantiene la misma API en 4.17.x). [PEGAR `git diff package.json` y `npm ls lodash`]

### 6.6 Verificación
[PEGAR `snyk test` DESPUÉS: lodash ya no aparece]. Si algo queda (p. ej. una transitiva de `sqlite3`
sin arreglo publicado), explicar aquí por qué permanece y la mitigación (no se usa en tiempo de
ejecución / solo se usa al instalar / se vigila con `snyk monitor`).

### 6.7 Prevención
Dependabot semanal (`.github/dependabot.yml`), `snyk test --severity-threshold=high` en CI que bloquea
el PR, `snyk monitor` para alertas de nuevos CVE y regla 5 de `.cursorrules`.

---

## 7. Vulnerabilidad 3 — Inyección de comandos del SO (SAST)

### 7.1 Ficha técnica y puntuación
- **Nombre:** OS Command Injection.  **Tipo:** SAST.  **CWE:** CWE-78.  **OWASP:** A05:2025 – Injection.
- **Severidad reportada por Snyk:** [PEGAR].
- **CVSS v3.1 (estimado):** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
- **Ubicación:** `app.js`, línea 86 (`GET /ping`).

### 7.2 Interpretación del riesgo
- **Vector:** red, sin autenticación, sin interacción.
- **CID:** **Alto en los tres**: el atacante ejecuta comandos con los permisos del proceso Node:
  puede leer archivos (C), modificarlos o instalar malware (I) y apagar o borrar el servicio (A).
- **Activo expuesto:** el servidor completo (y la red interna, como punto de pivote).
- **Condiciones:** solo acceso HTTP. **Exploit:** trivial y ampliamente documentado.
- **Reachability:** total.
- **Impacto empresarial:** compromiso total del servidor, robo de datos, ransomware, interrupción del negocio.

### 7.3 Causa raíz
Defecto de **diseño e implementación**: se usa `exec()`, que pasa la cadena a una **shell**
(`/bin/sh`), y se concatena la entrada del usuario. Los metacaracteres `;`, `&&`, `|` encadenan comandos.

```js
// ANTES - app.js línea 86
exec("ping -c 1 " + host, (err, stdout, stderr) => { ... });
```

### 7.4 Escenario de explotación controlada
`/ping?host=127.0.0.1;id` → la shell ejecuta `ping -c 1 127.0.0.1` **y luego** `id`, devolviendo el
usuario del sistema. [PEGAR captura del curl y de la prueba fallando]

### 7.5 Remediación
**Estrategia (dos capas):** 1) `execFile` **sin shell**, pasando los argumentos como arreglo
(el `;` deja de ser un separador de comandos); 2) **lista blanca** que solo acepta IPv4 o nombres de host válidos.

```js
// DESPUÉS
if (!hostValido(host)) return res.status(400).type("text/plain").send("Host inválido");
execFile("ping", ["-c", "1", host], { timeout: 5000 }, (err, stdout, stderr) => { ... });
```

**Funcionalidad:** `/ping?host=127.0.0.1` sigue funcionando; `127.0.0.1;id` responde `400`.

### 7.6 Verificación
[PEGAR `snyk code test` DESPUÉS sin CWE-78] y prueba `Command injection` en verde.

### 7.7 Prevención
ESLint (`security/detect-child-process`, prohibición de `child_process.exec`), regla Semgrep
`command-injection-exec`, regla 3 de `.cursorrules`, pre-commit y Quality Gate.

---

## 8. Comparación antes / después

| Evidencia | ANTES | DESPUÉS |
|---|---|---|
| `npm test` | 5 pasan / 4 fallan | 9 pasan / 0 fallan |
| `snyk code test` | [N] hallazgos | [N] hallazgos |
| `snyk test` | [N] vulnerabilidades | [N] vulnerabilidades |
| Login `admin'--` | 200 — entra como admin | 400 — Entrada inválida |
| `/ping?host=127.0.0.1;id` | ejecuta `id` | 400 — Host inválido |

Diff completo: `evidencias/diff_remediacion.txt`. [PEGAR `git diff --stat`]

## 9. Evidencias de reescaneo
[PEGAR capturas de `evidencias/despues/01_snyk_test.txt` y `03_snyk_code_test.txt`]

## 10. Controles preventivos y Quality Gate

| Control | Archivo | Qué detiene |
|---|---|---|
| Reglas para IA | `.cursorrules` | Que el asistente genere SQL concatenado, `exec`, HTML sin codificar o secretos |
| Linter | `eslint.config.js` (eslint-plugin-security) | `child_process` inseguro, regex peligrosas |
| SAST propio | `.semgrep.yml` (modo taint) | SQLi, XSS, command injection, secretos quemados |
| Pre-commit | `.githooks/pre-commit` | Secretos (gitleaks), `.env`, ESLint, Semgrep y Snyk Code alto antes del commit |
| Secret scanning | gitleaks en pre-commit y CI | Tokens/contraseñas en el historial |
| Quality Gate CI/CD | `.github/workflows/security.yml` | PR con dependencias o código de severidad alta/crítica |
| Bloqueo de PR | Protección de rama `main` (required status checks) | Fusionar sin pasar el Quality Gate |
| Política de dependencias | `.github/dependabot.yml` + `snyk monitor` | Dependencias desactualizadas / nuevos CVE |

[PEGAR captura del commit bloqueado por el hook]

## 11. Integración Cursor + MCP (solo si el docente la habilitó)
[COMPLETAR: herramienta MCP invocada, hallazgo analizado, propuesta del agente y qué revisaste/cambiaste. Si no se habilitó, escribir "No habilitado por el docente".]

## 12. Preguntas de cierre

1. **¿Cuál representa mayor riesgo real?** La inyección de comandos (V3): no requiere login, es trivial
   y compromete C, I y D del servidor entero.
2. **¿La mayor puntuación CVSS siempre se corrige primero?** No. CVSS mide gravedad teórica; el riesgo
   real depende del contexto. Ejemplo: CVE-2021-23337 (7.2) no era alcanzable, mientras que el ReDoS
   (5.3) sí recibía datos del usuario.
3. **Identificada vs. explotable:** identificada = la herramienta encontró el patrón o la versión;
   explotable = existe un camino real para que un atacante la active en este sistema (alcance, permisos, exposición).
4. **Impacto CID:** V1 C alta / I baja; V2 principalmente D; V3 C, I y D altas.
5. **¿Qué control lo habría detectado antes de producción?** SAST en el IDE/pre-commit (Snyk Code,
   Semgrep) para V1 y V3; SCA en CI (`snyk test`) para V2.
6. **¿Cómo llevarlo al CI/CD?** Workflow con `snyk test` y `snyk code test --severity-threshold=high`
   como *required status check* de la rama principal.
7. **Limitaciones de la automatización:** falsos positivos/negativos, Snyk Code no da CVSS ni sabe si
   el endpoint está expuesto, el *reachability* no siempre está disponible, y no entiende la lógica de negocio.
8. **¿Qué requiere criterio humano?** Priorizar por riesgo real, validar que la corrección no rompa la
   funcionalidad, revisar código sugerido por IA y decidir mitigaciones cuando no hay versión segura.

## 13. Conclusiones
[COMPLETAR con tus palabras: qué aprendiste, qué funcionó, qué no detectó la herramienta.]

## 14. Anexos
- `evidencias/antes/` y `evidencias/despues/` (salidas de Snyk en texto y JSON).
- `evidencias/diff_remediacion.txt`.
- Capturas numeradas y explicadas.

### Referencias
- NVD/OSV — CVE-2021-23337: https://osv.dev/vulnerability/CVE-2021-23337
- CVE-2025-13465 (lodash 4.17.23): https://cvefeed.io/vuln/detail/CVE-2025-13465
- OWASP Top 10:2025: https://owasp.org/Top10/2025/
- MITRE CWE-89, CWE-78, CWE-79: https://cwe.mitre.org/
- Snyk — Configure Snyk Code: https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-code/configure-snyk-code
