// Pruebas de SEGURIDAD (regresión).
// ANTES de corregir: estas pruebas FALLAN (prueban que la vulnerabilidad existe).
// DESPUÉS de corregir: deben PASAR (prueban que el ataque ya no funciona).
const { test, before, after } = require("node:test");
const assert = require("node:assert");
const app = require("../app");

let server, base;
before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${server.address().port}`;
  await new Promise((r) => setTimeout(r, 200));
});
after(() => server.close());

test("SQLi: login con admin'-- NO debe entrar sin contraseña", async () => {
  const r = await fetch(base + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin'--", password: "x" }),
  });
  assert.notStrictEqual(r.status, 200, "¡Vulnerable! Se entró como admin sin contraseña");
});

test("SQLi: ' OR '1'='1 NO debe listar todos los usuarios", async () => {
  const r = await fetch(base + "/users?name=" + encodeURIComponent("' OR '1'='1"));
  const j = await r.json().catch(() => []);
  assert.ok(!Array.isArray(j) || j.length <= 1, "¡Vulnerable! Se filtró toda la tabla");
});

test("XSS: <script> NO debe reflejarse sin codificar", async () => {
  const r = await fetch(base + "/search?q=" + encodeURIComponent("<script>alert(1)</script>"));
  const t = await r.text();
  assert.ok(!t.includes("<script>"), "¡Vulnerable! El script se refleja tal cual");
});

test("Command injection: ';' en host debe ser rechazado", async () => {
  const r = await fetch(base + "/ping?host=" + encodeURIComponent("127.0.0.1;echo INYECTADO"));
  const t = await r.text();
  assert.ok(!t.includes("INYECTADO"), "¡Vulnerable! Se ejecutó un comando inyectado");
});
