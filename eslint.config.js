// ESLint (configuración "flat", ESLint 9) con el plugin de seguridad.
// Detecta patrones peligrosos como child_process con datos no literales.
const security = require("eslint-plugin-security");

module.exports = [
  { ignores: ["node_modules/**", "evidencias/**"] },
  security.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "commonjs" },
    rules: {
      // Prohíbe importar "exec" (usa shell). Obliga a usar execFile.
      "no-restricted-properties": [
        "error",
        { object: "child_process", property: "exec", message: "Usa execFile sin shell (CWE-78)." },
      ],
      "security/detect-child-process": "error",
      "security/detect-non-literal-regexp": "warn",
    },
  },
];
