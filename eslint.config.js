import js from "@eslint/js";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

// Workspace scripts only; the npm package has its own config.
export default tseslint.config(
  { ignores: ["packages/**", "target/**", "fuzz/**"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  security.configs.recommended,
  {
    files: ["scripts/**/*.ts"],
    languageOptions: {
      globals: {
        ...globals.node,
        Bun: "readonly",
      },
    },
  },
);
