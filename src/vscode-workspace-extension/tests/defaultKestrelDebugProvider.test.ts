import { describe, it, expect } from "vitest";
import type * as vscode from "vscode";
import {
  createDefaultKestrelDebugProvider,
  type KestrelDefaultEnvHolder,
} from "../src/defaultKestrelDebugProvider";

const KESTREL_PATH_ENV = "ASPNETCORE_Kestrel__Certificates__Default__Path";
const KESTREL_PASSWORD_ENV =
  "ASPNETCORE_Kestrel__Certificates__Default__Password";

function holderWith(
  current: KestrelDefaultEnvHolder["current"]
): KestrelDefaultEnvHolder {
  return { current };
}

function baseConfig(
  overrides: Partial<vscode.DebugConfiguration> = {}
): vscode.DebugConfiguration {
  return {
    type: "coreclr",
    name: "Launch (https)",
    request: "launch",
    ...overrides,
  };
}

function resolve(
  provider: vscode.DebugConfigurationProvider,
  config: vscode.DebugConfiguration
): vscode.DebugConfiguration {
  // The "with substituted variables" hook is the one we register; tests
  // always exercise it. Folder/token are unused by the provider, so we
  // pass undefined / a stub.
  const fn = provider.resolveDebugConfigurationWithSubstitutedVariables;
  if (!fn) throw new Error("provider lacks resolveDebugConfigurationWithSubstitutedVariables");
  // token arg is optional in the API; folder is too. Both are unused.
  const result = fn(undefined, config);
  if (!result || result instanceof Promise) {
    throw new Error("provider returned undefined or a promise unexpectedly");
  }
  return result;
}

describe("createDefaultKestrelDebugProvider", () => {
  it("passes the config through untouched when no selection is active", () => {
    const provider = createDefaultKestrelDebugProvider(holderWith(undefined));
    const input = baseConfig({ env: { FOO: "bar" } });
    const out = resolve(provider, input);

    expect(out).toEqual(input);
    expect(out.env).toEqual({ FOO: "bar" });
  });

  it("adds the Path env when launch config has no env block", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/home/dev/.aspnet/dev-certs/https/kestrel-default.pfx" })
    );
    const out = resolve(provider, baseConfig());

    expect(out.env).toEqual({
      [KESTREL_PATH_ENV]:
        "/home/dev/.aspnet/dev-certs/https/kestrel-default.pfx",
    });
  });

  it("adds Path + Password when the selection carries a password", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/p.pfx", password: "hunter2" })
    );
    const out = resolve(provider, baseConfig());

    expect(out.env).toEqual({
      [KESTREL_PATH_ENV]: "/p.pfx",
      [KESTREL_PASSWORD_ENV]: "hunter2",
    });
  });

  it("preserves unrelated env vars set by launchSettings.json", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/p.pfx" })
    );
    const out = resolve(
      provider,
      baseConfig({
        env: {
          ASPNETCORE_ENVIRONMENT: "Development",
          OTEL_SERVICE_NAME: "sample",
        },
      })
    );

    expect(out.env).toEqual({
      ASPNETCORE_ENVIRONMENT: "Development",
      OTEL_SERVICE_NAME: "sample",
      [KESTREL_PATH_ENV]: "/p.pfx",
    });
  });

  it("overrides Path/Password values the launch config set to different values", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/new.pfx", password: "newpw" })
    );
    const out = resolve(
      provider,
      baseConfig({
        env: {
          [KESTREL_PATH_ENV]: "/stale.pfx",
          [KESTREL_PASSWORD_ENV]: "oldpw",
        },
      })
    );

    expect(out.env).toEqual({
      [KESTREL_PATH_ENV]: "/new.pfx",
      [KESTREL_PASSWORD_ENV]: "newpw",
    });
  });

  it("clears a stale __Password from the launch config when the selection is passwordless", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/p.pfx" })
    );
    const out = resolve(
      provider,
      baseConfig({
        env: {
          [KESTREL_PATH_ENV]: "/stale.pfx",
          [KESTREL_PASSWORD_ENV]: "oldpw",
        },
      })
    );

    expect(out.env).toEqual({
      [KESTREL_PATH_ENV]: "/p.pfx",
    });
    expect((out.env as Record<string, string>)[KESTREL_PASSWORD_ENV]).toBeUndefined();
  });

  it("does not mutate the input config object", () => {
    const provider = createDefaultKestrelDebugProvider(
      holderWith({ path: "/p.pfx" })
    );
    const input = baseConfig({ env: { ASPNETCORE_ENVIRONMENT: "Development" } });
    const inputSnapshot = JSON.parse(JSON.stringify(input));

    resolve(provider, input);

    expect(input).toEqual(inputSnapshot);
  });

  it("reads holder.current freshly on each resolve (provider isn't bound to a snapshot)", () => {
    const holder = holderWith(undefined);
    const provider = createDefaultKestrelDebugProvider(holder);

    // First launch: no selection.
    const first = resolve(provider, baseConfig());
    expect(first.env).toBeUndefined();

    // Selection becomes active.
    holder.current = { path: "/p.pfx" };
    const second = resolve(provider, baseConfig());
    expect(second.env).toEqual({ [KESTREL_PATH_ENV]: "/p.pfx" });

    // Selection cleared.
    holder.current = undefined;
    const third = resolve(provider, baseConfig());
    expect(third.env).toBeUndefined();
  });
});
