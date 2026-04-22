// Minimal vscode module stub for tests.
// Only the parts used by the source need to be present.

export const warningMessages: string[] = [];
export const errorMessages: string[] = [];

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(_msg: string) {
        // no-op in tests
      },
    };
  },
  showWarningMessage(message: string, ..._items: unknown[]) {
    warningMessages.push(message);
    return Promise.resolve(undefined);
  },
  showErrorMessage(message: string, ..._items: unknown[]) {
    errorMessages.push(message);
    return Promise.resolve(undefined);
  },
  showInformationMessage(_message: string, ..._items: unknown[]) {
    return Promise.resolve(undefined);
  },
};

interface ConfigMap {
  [section: string]: Record<string, unknown> | undefined;
}

const configStore: ConfigMap = {};

export function __setConfig(section: string, values: Record<string, unknown>) {
  configStore[section] = values;
}

export function __resetConfig() {
  for (const key of Object.keys(configStore)) {
    delete configStore[key];
  }
  warningMessages.length = 0;
  errorMessages.length = 0;
}

export const workspace = {
  getConfiguration(section?: string) {
    const values = (section && configStore[section]) || {};
    return {
      get<T>(key: string, defaultValue?: T): T | undefined {
        if (key in values) {
          return values[key] as T;
        }
        return defaultValue;
      },
    };
  },
};
