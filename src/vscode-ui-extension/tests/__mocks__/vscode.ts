// Minimal vscode module stub for tests.
// Only the parts used by the logger need to be present.

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(_msg: string) {
        // no-op in tests
      },
    };
  },
};

export const workspace = {
  getConfiguration(_section?: string) {
    return {
      get<T>(_key: string, defaultValue?: T): T | undefined {
        return defaultValue;
      },
    };
  },
};
