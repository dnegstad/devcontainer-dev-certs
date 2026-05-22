// Minimal vscode module stub for workspace extension tests.

export const window = {
  createOutputChannel(_name: string) {
    return {
      appendLine(_msg: string) {
        // no-op in tests
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

export const workspace = {
  getConfiguration(_section?: string) {
    return {
      get<T>(_key: string, defaultValue?: T): T | undefined {
        return defaultValue;
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
