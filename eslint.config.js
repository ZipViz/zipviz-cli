import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["tests/fixtures/signup-api/**/*.js", "test-vectors/signup-api/**/*.js"],
    languageOptions: { globals: { TextEncoder: "readonly", TextDecoder: "readonly", crypto: "readonly", structuredClone: "readonly", Request: "readonly", Response: "readonly" } },
    rules: { "@typescript-eslint/no-unused-vars": ["error", { varsIgnorePattern: "^_signature$" }] },
  },
  {
    languageOptions: {
      globals: { process: "readonly", console: "readonly", URL: "readonly", fetch: "readonly" },
    },
  },
);
