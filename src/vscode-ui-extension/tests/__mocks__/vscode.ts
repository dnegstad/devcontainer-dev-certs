// Minimal vscode module stub for tests.
// Only the parts used by the source need to be present.

export const warningMessages: string[] = [];
export const errorMessages: string[] = [];
export const logMessages: string[] = [];

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(msg: string) {
        logMessages.push(msg);
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
  logMessages.length = 0;
}

export const workspace = {
  getConfiguration(section?: string) {
    const values = (section ? configStore[section] : undefined) ?? {};
    return {
      get<T>(key: string, defaultValue?: T): T | undefined {
        if (key in values) {
          return values[key] as T;
        }
        return defaultValue;
      },
      // Values planted via __setConfig model an explicit user setting, so
      // they surface as globalValue (what settings.ts's renamed-setting
      // fallback inspects). Absent keys yield an all-undefined record,
      // matching the real API for a setting the user never touched.
      inspect<T>(key: string) {
        return {
          key: section ? `${section}.${key}` : key,
          globalValue: key in values ? (values[key] as T) : undefined,
          workspaceValue: undefined as T | undefined,
          workspaceFolderValue: undefined as T | undefined,
        };
      },
    };
  },
};

type L10nArg = string | number | boolean;
type L10nOptions = {
  message: string;
  args?: L10nArg[] | Record<string, L10nArg>;
  comment?: string | string[];
};

// Pass-through implementation matching `vscode.l10n.t` formatting semantics:
// English source strings are the keys, positional `{0}` / named `{name}`
// placeholders get substituted from args. Tests assert on the formatted output.
export const l10n = {
  t(message: string | L10nOptions, ...rest: L10nArg[]): string {
    let template: string;
    let substitutions: L10nArg[] | Record<string, L10nArg>;
    if (typeof message === "string") {
      template = message;
      substitutions = rest;
    } else {
      template = message.message;
      substitutions = message.args ?? [];
    }
    return template.replace(/\{(\w+)\}/g, (_match, key: string) => {
      if (Array.isArray(substitutions)) {
        const value = substitutions[Number(key)];
        return value === undefined ? "" : String(value);
      }
      const value = substitutions[key];
      return value === undefined ? "" : String(value);
    });
  },
};
