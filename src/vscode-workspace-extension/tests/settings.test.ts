import { describe, it, expect, beforeEach } from "vitest";
import { __setConfig, __resetConfig } from "./__mocks__/vscode";
import { getRenamedSetting } from "../src/settings";

/**
 * The settings normalization moved the three hyphenated-prefix settings
 * (`devcontainer-dev-certs.*`) under the canonical camelCase prefix
 * (`devcontainerDevCerts.*`). `getRenamedSetting` keeps existing user
 * config working: an explicit modern value wins, an explicit legacy
 * value is honored when the modern one is unset, and only then does the
 * default apply.
 */
describe("getRenamedSetting", () => {
  beforeEach(() => {
    __resetConfig();
  });

  it("returns the default when neither prefix has the setting", () => {
    expect(getRenamedSetting("autoInject", true)).toBe(true);
    expect(getRenamedSetting("autoInject", false)).toBe(false);
  });

  it("honors an explicitly-set legacy value when the modern name is unset", () => {
    __setConfig("devcontainer-dev-certs", { autoInject: false });
    expect(getRenamedSetting("autoInject", true)).toBe(false);
  });

  it("returns the modern value when set", () => {
    __setConfig("devcontainerDevCerts", { autoInject: false });
    expect(getRenamedSetting("autoInject", true)).toBe(false);
  });

  it("prefers the modern value over a conflicting legacy value", () => {
    __setConfig("devcontainerDevCerts", { autoInject: true });
    __setConfig("devcontainer-dev-certs", { autoInject: false });
    expect(getRenamedSetting("autoInject", false)).toBe(true);
  });

  it("an explicit modern false is not shadowed by a legacy true", () => {
    // The failure mode this guards: reading the modern name with
    // `get(key, default)` can't distinguish "user set false" from
    // "unset" for falsy values — inspect()-based precedence can.
    __setConfig("devcontainerDevCerts", { autoInject: false });
    __setConfig("devcontainer-dev-certs", { autoInject: true });
    expect(getRenamedSetting("autoInject", true)).toBe(false);
  });
});
