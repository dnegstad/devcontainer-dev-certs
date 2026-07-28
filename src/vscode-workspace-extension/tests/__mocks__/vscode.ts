// Minimal vscode module stub for workspace extension tests.

// Captured output-channel lines from the shared `log()` helper. Tests can
// snapshot / clear / assert against this array to verify what was (and
// wasn't) written to the Remote output channel.
export const logMessages: string[] = [];

export function __resetLogMessages() {
  logMessages.length = 0;
}

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(msg: string) {
        logMessages.push(msg);
      },
      show(_preserveFocus?: boolean) {
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
      update(_key: string, _value: unknown, _target?: unknown): Promise<void> {
        return Promise.resolve();
      },
    };
  },
};

export const commands = {
  executeCommand<T = unknown>(_command: string, ..._args: unknown[]): Promise<T | undefined> {
    return Promise.resolve(undefined);
  },
  registerCommand(_command: string, _callback: (...args: unknown[]) => unknown) {
    return { dispose() {} };
  },
};

export const debug = {
  registerDebugConfigurationProvider(
    _debugType: string,
    _provider: unknown,
    _triggerKind?: unknown
  ) {
    return { dispose() {} };
  },
};

export enum DebugConfigurationProviderTriggerKind {
  Initial = 1,
  Dynamic = 2,
}

export enum ConfigurationTarget {
  Global = 1,
  Workspace = 2,
  WorkspaceFolder = 3,
}

type L10nArg = string | number | boolean;
type L10nOptions = {
  message: string;
  args?: L10nArg[] | Record<string, L10nArg>;
  comment?: string | string[];
};

// Pass-through implementation of `vscode.l10n.t` for tests: English source
// strings are the keys; positional `{0}` and named `{name}` placeholders get
// substituted from the args so assertions can match the rendered output.
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
