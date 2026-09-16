import eslint from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [".demo/**", "node_modules/**"],
  },
  eslint.configs.recommended,
  {
    files: ["src/**/*.mjs", "test/**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      globals: globals.node,
      sourceType: "module",
    },
  },
];