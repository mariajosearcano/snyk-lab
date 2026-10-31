// Pruebas FUNCIONALES: deben pasar ANTES y DESPUÉS de corregir.
// Sirven para demostrar que la remediación no rompió la aplicación.
const { test, before, after } = require("node:test");
const assert = require("node:assert");
const app = require("../app");

let server, base;
before(async () => {
  server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  base = `http://127.0.0.1:${server.address().port}`;
  await new Promise((r) => setTimeout(r, 200)); // espera a que se cargue la BD
});
after(() => server.close());

test("la página principal responde", async () => {
  const r = await fetch(base + "/");
  assert.strictEqual(r.status, 200);
});

test("login correcto funciona", async () => {
  const r = await fetch(base + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ana", password: "Ana#2026" }),
  });
  const j = await r.json();
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.usuario, "ana");
});

test("login con clave errada es rechazado", async () => {
  const r = await fetch(base + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ana", password: "mala" }),
  });
  assert.strictEqual(r.status, 401);
});

test("buscar un usuario existente devuelve 1 resultado", async () => {
  const r = await fetch(base + "/users?name=luis");
  const j = await r.json();
  assert.strictEqual(j.length, 1);
});

test("la búsqueda muestra el texto buscado", async () => {
  const r = await fetch(base + "/search?q=portatil");
  const t = await r.text();
  assert.ok(t.includes("portatil"));
});
