import {
  describe,
  it,
  expect,
  beforeEach,
  vi,
} from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { Backend } from "@devcontainer-dev-certs/shared";

import type * as Shared from "@devcontainer-dev-certs/shared";

// Mock `selectBackend` so the test doesn't need a real `dotnet` install on
// PATH. We keep the rest of the shared module intact via `importActual`
// so the manager / cert primitives the SUT uses still work normally.
vi.mock("@devcontainer-dev-certs/shared", async () => {
  const actual = await vi.importActual<typeof Shared>(
    "@devcontainer-dev-certs/shared"
  );
  return {
    ...actual,
    selectBackend: vi.fn(),
  };
});

import { selectBackend } from "@devcontainer-dev-certs/shared";
import { CertProvider } from "../src/certProvider";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import type { CertManager } from "../src/cert/manager";
import type { DevCert, DevKey } from "../src/cert/types";
import { __resetConfig, __setConfig } from "./__mocks__/vscode";

const mockedSelectBackend = vi.mocked(selectBackend);

async function makeValidCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(now.getTime() + VALIDITY_DAYS * 86400_000);
  return generateCertificate(now, expiry);
}

interface ManagerSpyHandles {
  manager: CertManager;
  trustSpy: ReturnType<typeof vi.fn>;
  checkSpy: ReturnType<typeof vi.fn>;
}

/**
 * Build a CertManager-shaped mock that initially reports the cert as
 * absent / untrusted (so `ensureDotNetDevCert` is forced down the
 * provisioning path), then flips to present + trusted on subsequent
 * `check()` calls — simulating the side effect of a successful trust
 * step. `exportCert` writes real cert files into the export dir so the
 * subsequent base64-reading + cache-population step doesn't blow up.
 */
function buildManagerMock(cert: DevCert, key: DevKey, thumbprint: string): ManagerSpyHandles {
  let provisioned = false;
  const status = () => ({
    exists: provisioned,
    isTrusted: provisioned,
    thumbprint: provisioned ? thumbprint : null,
    notBefore: null,
    notAfter: null,
    version: 1,
  });
  const trustSpy = vi.fn(async () => {
    provisioned = true;
  });
  const checkSpy = vi.fn(async () => status());
  const manager = {
    check: checkSpy,
    trust: trustSpy,
    exportCert: vi.fn(
      async (format: "pfx" | "pem" | "root-pfx", outputDir: string) => {
        fs.mkdirSync(outputDir, { recursive: true });
        if (format === "pem") {
          fs.writeFileSync(path.join(outputDir, "aspnetcore-dev.pem"), cert.pem);
          fs.writeFileSync(path.join(outputDir, "aspnetcore-dev.key"), key.pem);
        } else if (format === "pfx") {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev.pfx"),
            Buffer.from("fake-pfx")
          );
        } else {
          fs.writeFileSync(
            path.join(outputDir, "aspnetcore-dev-root.pfx"),
            Buffer.from("fake-root")
          );
        }
      }
    ),
    trustExternalCertificate: vi.fn(async () => {}),
  } as unknown as CertManager;
  return { manager, trustSpy, checkSpy };
}

/**
 * Construct a fake Backend that records every call to its `generate` and
 * flips the supplied "is now trusted" state via the manager mock so the
 * downstream export path sees a populated platform store.
 */
function fakeBackend(
  kind: "native" | "dotnet",
  onGenerate: () => void
): Backend {
  return {
    kind,
    isAvailable: vi.fn(() => Promise.resolve(true)),
    generate: vi.fn(async () => {
      onGenerate();
      return {
        pfxPath: "/dev/null/pfx",
        pemPath: "/dev/null/pem",
        pemKeyPath: null,
        thumbprint: "FAKE",
        trusted: true,
        backendUsed: kind,
      };
    }),
  };
}

beforeEach(() => {
  __resetConfig();
  mockedSelectBackend.mockReset();
});

describe("CertProvider.provisionViaConfiguredBackend", () => {
  it("uses the in-process CertManager.trust() when hostCertGenerator is 'native'", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager, trustSpy } = buildManagerMock(cert, key, thumbprint);

    // `selectBackend("native")` returns a native backend; the provider
    // sees `kind: "native"` and routes to the pre-configured
    // CertManager rather than calling `backend.generate()`.
    mockedSelectBackend.mockResolvedValue(fakeBackend("native", () => {
      throw new Error("native backend.generate should not run; native path defers to certManager.trust()");
    }));

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      hostCertGenerator: "native",
    });

    const provider = new CertProvider(manager);
    await provider.getCertMaterial(true);

    expect(mockedSelectBackend).toHaveBeenCalledWith("native");
    expect(trustSpy).toHaveBeenCalledTimes(1);
  });

  it("defers to selectBackend('auto') when hostCertGenerator is unset", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager, trustSpy } = buildManagerMock(cert, key, thumbprint);

    // 'auto' resolved to native — selectBackend returned a native backend.
    // CertProvider should use the configured manager.trust() rather than
    // the bare CertManager inside the shared NativeBackend so the
    // extension's l10n + Linux NSS reporter wiring is preserved.
    mockedSelectBackend.mockResolvedValue(fakeBackend("native", () => {
      throw new Error("native backend.generate should not run for 'auto' → native");
    }));

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      // hostCertGenerator intentionally absent — default is 'auto'.
    });

    const provider = new CertProvider(manager);
    await provider.getCertMaterial(true);

    expect(mockedSelectBackend).toHaveBeenCalledWith("auto");
    expect(trustSpy).toHaveBeenCalledTimes(1);
  });

  it("dispatches to backend.generate() when selectBackend returns a dotnet backend", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager, trustSpy } = buildManagerMock(cert, key, thumbprint);

    // Simulate dotnet's side effect: after `generate()` runs, the
    // platform store has a trusted cert. We bridge to the same state
    // flip the native trustSpy would have produced by calling trustSpy
    // ourselves from within the fake generate.
    let backendCalled = false;
    mockedSelectBackend.mockResolvedValue(
      fakeBackend("dotnet", () => {
        backendCalled = true;
        void trustSpy();
      })
    );

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      hostCertGenerator: "dotnet",
    });

    const provider = new CertProvider(manager);
    await provider.getCertMaterial(true);

    expect(mockedSelectBackend).toHaveBeenCalledWith("dotnet");
    expect(backendCalled).toBe(true);
    // CertManager.trust() must NOT have been called directly by
    // CertProvider when the dotnet backend runs — provisioning is the
    // backend's job, not the manager's.
    expect(trustSpy).toHaveBeenCalledTimes(1);
    // (The one call we saw was from the fake generate itself, simulating
    // the dotnet side effect.)
  });

  it("propagates selectBackend errors so the user sees the failure", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager } = buildManagerMock(cert, key, thumbprint);

    mockedSelectBackend.mockRejectedValue(
      new Error("Requested --backend dotnet but the `dotnet` CLI was not found on PATH.")
    );

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      hostCertGenerator: "dotnet",
    });

    const provider = new CertProvider(manager);
    await expect(provider.getCertMaterial(true)).rejects.toThrow(
      /dotnet.*not found on PATH/
    );
  });

  it("forwards the linuxNssTrustReporter to the dotnet backend", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager, trustSpy } = buildManagerMock(cert, key, thumbprint);

    let receivedReporter: unknown = "uncalled";
    mockedSelectBackend.mockResolvedValue({
      kind: "dotnet",
      isAvailable: () => Promise.resolve(true),
      generate: vi.fn(async (opts: Shared.GenerateOptions) => {
        receivedReporter = opts.linuxNssTrustReporter;
        await trustSpy();
        return {
          pfxPath: "/dev/null/pfx",
          pemPath: "/dev/null/pem",
          pemKeyPath: null,
          thumbprint: "FAKE",
          trusted: true,
          backendUsed: "dotnet" as const,
        };
      }),
    });

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      hostCertGenerator: "dotnet",
    });

    const sentinelReporter: Shared.LinuxNssTrustReporter = () => {
      /* test-supplied reporter, identity matters for the assertion */
    };
    const provider = new CertProvider(manager, sentinelReporter);
    await provider.getCertMaterial(true);

    // Regression guard for the gap where the dotnet branch silently
    // dropped the reporter on Linux. The exact identity must round-trip
    // — substituting a different no-op reporter would silently break
    // the host extension's NSS-failure toast.
    expect(receivedReporter).toBe(sentinelReporter);
  });

  it("cleans up the per-provisioning tmp dir even when the backend throws", async () => {
    const { cert, key, thumbprint } = await makeValidCert();
    const { manager } = buildManagerMock(cert, key, thumbprint);

    let createdDir: string | null = null;
    mockedSelectBackend.mockResolvedValue({
      kind: "dotnet",
      isAvailable: () => Promise.resolve(true),
      generate: vi.fn(async (opts: Shared.GenerateOptions) => {
        // The provisioning tmp dir exists at the point generate runs.
        // We capture it so we can assert it gets cleaned up on the
        // exception path below.
        createdDir = opts.outDir;
        expect(fs.existsSync(opts.outDir)).toBe(true);
        throw new Error("simulated dotnet failure mid-generation");
      }),
    });

    __setConfig("devcontainerDevCerts", {
      generateDotNetCert: true,
      hostCertGenerator: "dotnet",
    });

    const provider = new CertProvider(manager);
    await expect(provider.getCertMaterial(true)).rejects.toThrow(/simulated dotnet failure/);
    expect(createdDir).not.toBeNull();
    expect(fs.existsSync(createdDir!)).toBe(false);
    // Sanity: the tmp dir really did live under os.tmpdir().
    expect(createdDir!.startsWith(os.tmpdir())).toBe(true);
  });
});
