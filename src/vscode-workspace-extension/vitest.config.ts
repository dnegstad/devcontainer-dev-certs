import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    setupFiles: ["./vitest.setup.ts"],
  },
  resolve: {
    alias: {
      vscode: new URL("tests/__mocks__/vscode.ts", import.meta.url).pathname,
    },
  },
});
