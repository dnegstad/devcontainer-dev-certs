import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { NativeBackend, loadPfx } from "@devcontainer-dev-certs/shared";

/**
 * NativeBackend has two distinct code paths picked by `noTrust`.
 *
 * - `noTrust: true`: generate purely in memory, write only to `outDir`.
 *   The platform store (`~/.dotnet/corefx/cryptography/x509stores/my/`
 *   on Linux/macOS) must NOT be touched — the caller has explicitly
 *   opted out of host-side cert installation.
 * - `noTrust: false`: drive `CertManager` end-to-end, including writing
 *   to the platform store. That's the host-trust contract; we don't
 *   test that path here because it requires interactive trust prompts
 *   on macOS/Windows and root NSS hooks on Linux.
 *
 * Both paths are exercised on a redirected `$HOME` so any accidental
 * store write would land in our tmpdir where we can audit it.
 */
describe("NativeBackend.generate with --no-trust", () => {
  let originalHome: string | undefined;
  let fakeHome: string;
  let outDir: string;
  let backend: NativeBackend;

  beforeEach(() => {
    originalHome = process.env.HOME;
    fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-nativebackend-home-"));
    process.env.HOME = fakeHome;
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-nativebackend-out-"));
    backend = new NativeBackend();
  });

  afterEach(() => {
    fs.rmSync(fakeHome, { recursive: true, force: true });
    fs.rmSync(outDir, { recursive: true, force: true });
    if (originalHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = originalHome;
    }
  });

  it("writes pfx + pem + key into outDir and reports trusted=false", async () => {
    const result = await backend.generate({ outDir, noTrust: true });

    expect(result.trusted).toBe(false);
    expect(result.backendUsed).toBe("native");
    expect(fs.existsSync(result.pfxPath)).toBe(true);
    expect(fs.existsSync(result.pemPath)).toBe(true);
    expect(result.pemKeyPath).not.toBeNull();
    expect(fs.existsSync(result.pemKeyPath!)).toBe(true);
    expect(result.pfxPath).toBe(path.join(outDir, "aspnetcore-dev.pfx"));
    expect(result.pemPath).toBe(path.join(outDir, "aspnetcore-dev.pem"));
    expect(result.pemKeyPath).toBe(path.join(outDir, "aspnetcore-dev.key"));
  });

  it("reports a SHA-1 thumbprint that matches the reparsed PFX", async () => {
    const result = await backend.generate({ outDir, noTrust: true });

    const loaded = await loadPfx(result.pfxPath);
    expect(loaded.cert.thumbprintSha1).toBe(result.thumbprint);
    // SHA-1 is 40 hex chars; uppercase per shared cert primitives.
    expect(result.thumbprint).toMatch(/^[0-9A-F]{40}$/);
  });

  it("does NOT write into the platform store directory under HOME", async () => {
    await backend.generate({ outDir, noTrust: true });

    // The .NET X509Store on Linux/macOS lives under
    // ~/.dotnet/corefx/cryptography/x509stores/my/. With our redirected
    // $HOME, that translates to fakeHome/.dotnet/... — and since the
    // noTrust path bypasses CertManager entirely, nothing under fakeHome
    // should have been created.
    const storeDir = path.join(
      fakeHome,
      ".dotnet",
      "corefx",
      "cryptography",
      "x509stores",
      "my"
    );
    expect(fs.existsSync(storeDir)).toBe(false);

    // Belt-and-suspenders: nothing at all under fakeHome.
    const homeEntries = fs.readdirSync(fakeHome);
    expect(homeEntries).toEqual([]);
  });

  it("produces a fresh cert on every invocation (no store-based reuse)", async () => {
    const first = await backend.generate({ outDir, noTrust: true });
    fs.rmSync(outDir, { recursive: true });
    fs.mkdirSync(outDir);
    const second = await backend.generate({ outDir, noTrust: true });

    // Two separate generations → two distinct serial numbers / thumbprints.
    // The noTrust path is intentionally not idempotent: with no store
    // residency, there's no "existing cert" for the backend to find and
    // reuse.
    expect(second.thumbprint).not.toBe(first.thumbprint);
  });
});
