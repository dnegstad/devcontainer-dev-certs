import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
  resolve: {
    alias: {
      // The logger imports vscode which isn't available in test.
      // Provide a lightweight stub so modules that transitively import
      // the logger can be loaded without the real VS Code API.
      vscode: new URL("tests/__mocks__/vscode.ts", import.meta.url).pathname,
    },
  },
});
