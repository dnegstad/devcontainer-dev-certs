import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { initLogger } from "@devcontainer-dev-certs/shared";
import { logMessages } from "./__mocks__/vscode";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";
import { buildPfx } from "../src/cert/pfx";
import { type DevCert, type DevKey } from "../src/cert/types";


vi.mock("../src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

import {
  WindowsCertificateStore,
  type PsCandidate,
  type PsSkipped,
} from "../src/platform/windowsStore";
import { runProcess } from "../src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

initLogger("test");

/**
 * Wire `runProcess` to behave like PowerShell:
 *  - First call (the pwsh-presence probe) succeeds with 'ok'.
 *  - Subsequent calls return the supplied enumeration JSON.
 *
 * Returns the temp PFXs so individual tests can assert they're unlinked.
 */
function setupPsMock(opts: {
  candidates?: PsCandidate[];
  skipped?: PsSkipped[];
}) {
  let psProbed = false;
  mockedRunProcess.mockImplementation(async (cmd: string, args: readonly string[]) => {
    if (cmd === "pwsh" && args.includes("echo ok") && !psProbed) {
      psProbed = true;
      return { exitCode: 0, stdout: "ok", stderr: "" };
    }
    // Enumeration call — script is the last arg.
    const payload = {
      candidates: opts.candidates ?? [],
      skipped: opts.skipped ?? [],
    };
    return {
      exitCode: 0,
      stdout: JSON.stringify(payload),
      stderr: "",
    };
  });
}

describe("WindowsCertificateStore.findExistingDevCert", () => {
  let store: WindowsCertificateStore;
  let tmpDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    // Each test instantiates a fresh store, but module-level resolvedPwsh
    // caches between tests. The pwsh probe is short-circuited by setupPsMock.
    logMessages.length = 0;
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-win-"));
    store = new WindowsCertificateStore("CurrentUser");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  async function writeExportablePfx(opts: {
    notAfter?: Date;
  } = {}): Promise<{
    cert: DevCert;
    key: DevKey;
    thumbprint: string;
    pfxPath: string;
    notBefore: Date;
    notAfter: Date;
  }> {
    const now = new Date();
    const exp = opts.notAfter ?? new Date(now.getTime() + VALIDITY_DAYS * 86400 * 1000);
    const generated = await generateCertificate(now, exp);
    const pfxBytes = await buildPfx({
      cert: generated.cert,
      key: generated.key,
      password: "export",
    });
    const pfxPath = path.join(tmpDir, `${generated.thumbprint}.pfx`);
    fs.writeFileSync(pfxPath, pfxBytes);
    return { ...generated, pfxPath, notBefore: now, notAfter: exp };
  }

  it("returns the cert when a single candidate is present", async () => {
    const c = await writeExportablePfx();
    setupPsMock({
      candidates: [
        {
          thumbprint: c.thumbprint,
          pfxPath: c.pfxPath,
          subjectCN: "localhost",
          notBefore: c.notBefore.toISOString(),
          notAfter: c.notAfter.toISOString(),
        },
      ],
    });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(c.thumbprint);
    expect(fs.existsSync(c.pfxPath)).toBe(false); // temp cleaned up
  });

  it("picks the cert with the later notAfter when versions are equal", async () => {
    const a = await writeExportablePfx({
      notAfter: new Date(Date.now() + 100 * 86400 * 1000),
    });
    const b = await writeExportablePfx({
      notAfter: new Date(Date.now() + 300 * 86400 * 1000),
    });
    const winner = b; // later notAfter wins on equal version
    setupPsMock({
      candidates: [a, b].map((c) => ({
        thumbprint: c.thumbprint,
        pfxPath: c.pfxPath,
        subjectCN: "localhost",
        notBefore: c.notBefore.toISOString(),
        notAfter: c.notAfter.toISOString(),
      })),
    });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(winner.thumbprint);
    // Selection log should have fired.
    const sel = logMessages.find((m) =>
      m.includes("Multiple valid ASP.NET dev certs")
    );
    expect(sel).toBeDefined();
    expect(sel).toContain("Windows CurrentUser\\My");
    // Both temp PFXs cleaned up.
    expect(fs.existsSync(a.pfxPath)).toBe(false);
    expect(fs.existsSync(b.pfxPath)).toBe(false);
  });

  it("logs unusable warnings for skipped[] entries that look like dev certs", async () => {
    const c = await writeExportablePfx();
    const now = new Date();
    const exp = new Date(now.getTime() + 100 * 86400 * 1000);
    setupPsMock({
      candidates: [
        {
          thumbprint: c.thumbprint,
          pfxPath: c.pfxPath,
          subjectCN: "localhost",
          notBefore: c.notBefore.toISOString(),
          notAfter: c.notAfter.toISOString(),
        },
      ],
      skipped: [
        {
          thumbprint: "DEADBEEF",
          subjectCN: "localhost",
          notBefore: now.toISOString(),
          notAfter: exp.toISOString(),
          reasonCode: "not-exportable",
        },
        {
          // Expired — should NOT warn (silent skip).
          thumbprint: "CAFE0000",
          subjectCN: "localhost",
          notBefore: new Date(now.getTime() - 365 * 86400 * 1000).toISOString(),
          notAfter: new Date(now.getTime() - 1 * 86400 * 1000).toISOString(),
          reasonCode: "no-private-key",
        },
        {
          // Wrong CN — should NOT warn.
          thumbprint: "BEEF0000",
          subjectCN: "other.example.com",
          notBefore: now.toISOString(),
          notAfter: exp.toISOString(),
          reasonCode: "no-private-key",
        },
      ],
    });

    const found = await store.findExistingDevCert();
    expect(found?.thumbprint).toBe(c.thumbprint);

    const unusable = logMessages.filter((m) =>
      m.includes("Skipping ASP.NET dev cert")
    );
    expect(unusable).toHaveLength(1);
    expect(unusable[0]).toContain("DEADBEEF");
    expect(unusable[0]).toContain("not exportable");
  });

  it("returns null when only skipped[] entries exist", async () => {
    const now = new Date();
    const exp = new Date(now.getTime() + 100 * 86400 * 1000);
    setupPsMock({
      candidates: [],
      skipped: [
        {
          thumbprint: "DEADBEEF",
          subjectCN: "localhost",
          notBefore: now.toISOString(),
          notAfter: exp.toISOString(),
          reasonCode: "not-exportable",
        },
      ],
    });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();

    const unusable = logMessages.filter((m) =>
      m.includes("Skipping ASP.NET dev cert")
    );
    expect(unusable).toHaveLength(1);
  });

  it("cleans up temp PFXs even when no candidate is selected", async () => {
    // Build a candidate that points at a nonexistent file — load will fail.
    setupPsMock({
      candidates: [
        {
          thumbprint: "ABC123",
          pfxPath: path.join(tmpDir, "nonexistent.pfx"),
          subjectCN: "localhost",
          notBefore: new Date().toISOString(),
          notAfter: new Date(Date.now() + 86400 * 1000).toISOString(),
        },
      ],
    });

    const found = await store.findExistingDevCert();
    expect(found).toBeNull();
  });
});
