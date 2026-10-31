// =====================================================================
//  APLICACIÓN DE LABORATORIO - VERSIÓN CORREGIDA (DESPUÉS)
//  Práctica 5: Implementación Práctica Snyk CLI
// =====================================================================
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const { execFile } = require("child_process");
const crypto = require("crypto");
const _ = require("lodash");
const { escapeHtml, hostValido, usuarioValido } = require("./lib/seguridad");

const app = express();
app.use(express.json());

// [FIX VULN 4] El secreto se lee de una variable de entorno, no del código.
// Si no existe, se genera uno aleatorio por ejecución (solo para el laboratorio).
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString("hex");

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["admin", "Adm1n#Lab", "admin"]);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["ana", "Ana#2026", "user"]);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["luis", "Luis#2026", "user"]);
});

function firmarToken(username) {
  return crypto.createHmac("sha256", TOKEN_SECRET).update(username).digest("hex");
}

app.get("/", (req, res) => {
  res.send("Snyk Lab funcionando. Rutas: POST /login, GET /users?name=, GET /search?q=, GET /ping?host=");
});

// [FIX VULN 1] Consulta parametrizada: los "?" hacen que la entrada se trate
// como DATO y nunca como parte del código SQL. Además se valida el formato.
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!usuarioValido(username) || typeof password !== "string") {
    return res.status(400).json({ ok: false, mensaje: "Entrada inválida" });
  }
  const query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
  db.get(query, [username, password], (err, row) => {
    if (err) return res.status(500).json({ error: "Error interno" }); // no se filtran detalles
    if (!row) return res.status(401).json({ ok: false, mensaje: "Credenciales inválidas" });
    res.json({ ok: true, usuario: row.username, rol: row.role, token: firmarToken(row.username) });
  });
});

app.get("/users", (req, res) => {
  const name = _.trim(String(req.query.name || "")); // lodash ya actualizado
  if (!usuarioValido(name)) return res.status(400).json({ error: "Nombre inválido" });
  db.all("SELECT id, username, role FROM users WHERE username = ?", [name], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error interno" });
    res.json(rows);
  });
});

// [FIX VULN 2] Se codifica la salida HTML: <script> se muestra como texto.
app.get("/search", (req, res) => {
  const q = escapeHtml(req.query.q || "");
  res.send("<h1>Resultados para: " + q + "</h1><p>No se encontraron productos.</p>");
});

// [FIX VULN 3] execFile NO usa shell (";", "&&", "|" no se interpretan)
// y además se valida el host con lista blanca.
app.get("/ping", (req, res) => {
  const host = String(req.query.host || "127.0.0.1");
  if (!hostValido(host)) return res.status(400).type("text/plain").send("Host inválido");
  execFile("ping", ["-c", "1", host], { timeout: 5000 }, (err, stdout, stderr) => {
    res.type("text/plain").send(stdout || stderr || "Sin respuesta");
  });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, "127.0.0.1", () => console.log(`Snyk Lab (CORREGIDO) en http://127.0.0.1:${PORT}`));
}

module.exports = app;
