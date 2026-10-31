// Funciones de seguridad reutilizables (sin dependencias externas).
// Se copian a ./lib/seguridad.js durante la remediación.

// Codifica caracteres especiales de HTML -> corrige XSS (CWE-79)
function escapeHtml(texto) {
  return String(texto)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Lista blanca para host: solo IPv4 o nombre de dominio simple.
// Corrige inyección de comandos (CWE-78) junto con execFile (sin shell).
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOSTNAME = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function hostValido(host) {
  if (typeof host !== "string") return false;
  return IPV4.test(host) || HOSTNAME.test(host);
}

// Valida nombres de usuario: letras, números, punto, guion y guion bajo (máx. 32).
function usuarioValido(nombre) {
  return typeof nombre === "string" && /^[a-zA-Z0-9._-]{1,32}$/.test(nombre);
}

module.exports = { escapeHtml, hostValido, usuarioValido };
