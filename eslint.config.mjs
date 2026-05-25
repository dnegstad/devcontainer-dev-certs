// @ts-check
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

/**
 * Root flat config covering every workspace. Each workspace has its own
 * `tsconfig.lint.json` that includes both `src/` and `tests/` so the typed
 * rules (no-floating-promises, await-thenable, etc.) work in tests too.
 *
 * Strategy:
 *   - typescript-eslint `recommended-type-checked` as the base.
 *   - Correctness-only overlay: things that surface real bugs.
 *   - No stylistic rules — the tree is already consistent and we don't want
 *     ESLint fighting whatever formatter someone runs locally.
 */
export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      ".out/**",
      "**/*.js",
      "**/*.mjs",
      "**/*.cjs",
      // Build/test config files live outside the source tsconfigs and would
      // need their own project entry; they're tiny and bundler-typechecked
      // separately.
      "**/vitest.config.ts",
      "**/esbuild.mjs",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    files: ["src/**/*.ts", "**/src/**/*.ts", "**/tests/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node },
      parserOptions: {
        project: [
          "./src/shared/tsconfig.json",
          "./src/cli/tsconfig.lint.json",
          "./src/vscode-ui-extension/tsconfig.lint.json",
          "./src/vscode-workspace-extension/tsconfig.lint.json",
        ],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // --- Correctness overlay (additions to recommended-type-checked) ---

      // Floating promises are the highest-value typed rule for this codebase
      // now that the cert stack is async — keep it on as an error.
      "@typescript-eslint/no-floating-promises": "error",

      // Force `import type` for type-only imports so esbuild can drop them
      // cleanly and we don't accidentally pull runtime modules into the
      // bundle just for their types.
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "inline-type-imports" },
      ],

      // `??` over `||` for nullable defaults — `||` masks empty strings and
      // 0, both of which are meaningful in the cert flows (e.g. empty PFX
      // password is intentional).
      "@typescript-eslint/prefer-nullish-coalescing": "error",

      // Allow `_`-prefixed unused params/vars (we already use this convention
      // for ignored callback args in the platform stores).
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],

      // The base rule fires on the same code; defer to the typed version.
      "no-unused-vars": "off",

      // --- Knobs we deliberately loosen ---

      // The ASN.1 / PKCS#12 layer interacts with libraries whose types model
      // schemas as `any` in places (pkijs parsedValue, etc.). Downgrading
      // these to warn keeps the signal without blocking the build.
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unsafe-assignment": "warn",
      "@typescript-eslint/no-unsafe-member-access": "warn",
      "@typescript-eslint/no-unsafe-call": "warn",
      "@typescript-eslint/no-unsafe-argument": "warn",
      "@typescript-eslint/no-unsafe-return": "warn",
    },
  },
  {
    // Tests can be a little looser — non-null assertions and explicit `any`
    // are fine when wiring up fixtures, and `expect(mock).toHaveBeenCalled()`
    // intentionally passes a method reference (which `unbound-method` flags).
    files: ["**/tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/unbound-method": "off",
      // `vi.fn(async () => ...)` mocks intentionally have no await.
      "@typescript-eslint/require-await": "off",
    },
  }
);
