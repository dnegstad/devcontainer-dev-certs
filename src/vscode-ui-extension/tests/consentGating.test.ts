import { describe, it, expect, vi } from "vitest";
import { resolveDotnetProvisioning } from "../src/extension";

function makeDeps(overrides: {
  args?: { includeDotNetDev?: boolean; includeUserCerts?: boolean } | undefined;
  hostWantsDotNet?: boolean;
  autoProvision?: boolean;
  status?: { exists: boolean; isTrusted: boolean };
  hasPriorConsent?: boolean;
  promptAnswer?: boolean;
}) {
  const checkCert = vi.fn(async () =>
    overrides.status ?? { exists: false, isTrusted: false }
  );
  const hasPriorConsent = vi.fn(() => overrides.hasPriorConsent === true);
  const recordConsent = vi.fn(async () => {});
  const promptUser = vi.fn(async () => overrides.promptAnswer === true);
  return {
    args: overrides.args,
    hostWantsDotNet: overrides.hostWantsDotNet ?? true,
    autoProvision: overrides.autoProvision ?? true,
    checkCert,
    hasPriorConsent,
    recordConsent,
    promptUser,
  };
}

describe("resolveDotnetProvisioning gating", () => {
  it("skips the prompt and the cert when the host setting generateDotNetCert=false", async () => {
    const deps = makeDeps({ hostWantsDotNet: false });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(false);
    expect(deps.checkCert).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("skips the prompt when the workspace ext passes includeDotNetDev=false", async () => {
    const deps = makeDeps({ args: { includeDotNetDev: false } });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(false);
    expect(deps.checkCert).not.toHaveBeenCalled();
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("skips the prompt when autoProvision is disabled", async () => {
    const deps = makeDeps({ autoProvision: false });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(false);
    expect(deps.promptUser).not.toHaveBeenCalled();
  });

  it("still skips the prompt when the cert is already trusted on the host", async () => {
    const deps = makeDeps({ status: { exists: true, isTrusted: true } });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(true);
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("skips the prompt when prior consent has been recorded", async () => {
    const deps = makeDeps({
      status: { exists: false, isTrusted: false },
      hasPriorConsent: true,
    });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(true);
    expect(deps.promptUser).not.toHaveBeenCalled();
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("prompts and records consent when accepted", async () => {
    const deps = makeDeps({
      status: { exists: false, isTrusted: false },
      promptAnswer: true,
    });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(true);
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    expect(deps.recordConsent).toHaveBeenCalledTimes(1);
  });

  it("prompts and bails without recording consent when declined", async () => {
    const deps = makeDeps({
      status: { exists: false, isTrusted: false },
      promptAnswer: false,
    });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.includeDotNetDev).toBe(false);
    expect(deps.promptUser).toHaveBeenCalledTimes(1);
    expect(deps.recordConsent).not.toHaveBeenCalled();
  });

  it("preserves includeUserCerts in the effective args regardless of the dotnet decision", async () => {
    const declinedHost = await resolveDotnetProvisioning(
      makeDeps({ hostWantsDotNet: false, args: { includeUserCerts: true } })
    );
    expect(declinedHost.effectiveArgs.includeUserCerts).toBe(true);

    const explicitFalse = await resolveDotnetProvisioning(
      makeDeps({ args: { includeDotNetDev: false, includeUserCerts: false } })
    );
    expect(explicitFalse.effectiveArgs.includeUserCerts).toBe(false);
  });

  it("defaults missing args to inclusive (matches v2 contract)", async () => {
    const deps = makeDeps({
      args: undefined,
      status: { exists: true, isTrusted: true },
    });
    const decision = await resolveDotnetProvisioning(deps);

    expect(decision.effectiveArgs.includeDotNetDev).toBe(true);
    expect(decision.effectiveArgs.includeUserCerts).toBe(true);
    expect(decision.includeDotNetDev).toBe(true);
  });
});
