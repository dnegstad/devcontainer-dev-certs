import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as vscode from "vscode";
import { isRemoteContext } from "../src/extension";

const { __setRemoteName, ExtensionMode } = vscode as unknown as {
  __setRemoteName: (name: string | undefined) => void;
  ExtensionMode: { Production: number; Development: number; Test: number };
};

const ENV_VAR = "DEVCONTAINER_DEV_CERTS_TEST_REMOTE";

function contextWith(extensionMode: number): vscode.ExtensionContext {
  return { extensionMode } as unknown as vscode.ExtensionContext;
}

describe("isRemoteContext", () => {
  let priorEnv: string | undefined;

  beforeEach(() => {
    priorEnv = process.env[ENV_VAR];
    delete process.env[ENV_VAR];
    __setRemoteName(undefined);
  });

  afterEach(() => {
    if (priorEnv === undefined) delete process.env[ENV_VAR];
    else process.env[ENV_VAR] = priorEnv;
    __setRemoteName(undefined);
  });

  it("is remote whenever VS Code reports a remote authority", () => {
    __setRemoteName("dev-container");
    expect(isRemoteContext(contextWith(ExtensionMode.Production))).toBe(true);
  });

  it("is not remote in a plain local window", () => {
    expect(isRemoteContext(contextWith(ExtensionMode.Development))).toBe(false);
  });

  /**
   * The assertion that makes the test-only seam acceptable in shipped code.
   *
   * ExtensionMode.Production is what VS Code assigns to every INSTALLED
   * extension — marketplace VSIX, sideloaded VSIX, `--install-extension`
   * copy. If this ever returns true, the escape hatch is live in users'
   * editors and a plain environment variable can make the extension write
   * certificates into a non-container home directory. Do not relax it.
   */
  it("refuses the test override in Production, whatever the env says", () => {
    for (const value of ["1", "true", "yes", "on", "TRUE"]) {
      process.env[ENV_VAR] = value;
      expect(isRemoteContext(contextWith(ExtensionMode.Production))).toBe(false);
    }
  });

  it("honors the test override in Development and Test modes", () => {
    process.env[ENV_VAR] = "1";
    expect(isRemoteContext(contextWith(ExtensionMode.Development))).toBe(true);
    expect(isRemoteContext(contextWith(ExtensionMode.Test))).toBe(true);
  });

  it("ignores an unset or falsy override outside Production", () => {
    for (const value of [undefined, "", "0", "false", "no", "off"]) {
      if (value === undefined) delete process.env[ENV_VAR];
      else process.env[ENV_VAR] = value;
      expect(isRemoteContext(contextWith(ExtensionMode.Development))).toBe(
        false
      );
    }
  });
});
