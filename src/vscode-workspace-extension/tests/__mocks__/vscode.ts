// Minimal vscode module stub for workspace extension tests.

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(_msg: string) {
        // no-op in tests
      },
    };
  },
  showWarningMessage() {
    return Promise.resolve(undefined);
  },
  showErrorMessage() {
    return Promise.resolve(undefined);
  },
  showInformationMessage() {
    return Promise.resolve(undefined);
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
