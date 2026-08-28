import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Mock runProcess to simulate certutil and which commands. Target the
// shared internal module that `trustInNss` actually imports from — mocking
// the extension's re-export shim would leave the implementation calling
// the real runProcess.
vi.mock("@devcontainer-dev-certs/shared/src/platform/processUtil", () => ({
  runProcess: vi.fn(),
}));

// Mock os.homedir to use a temp directory for browser profile discovery
let mockHomeDir: string;
vi.mock("os", async (importOriginal) => {
  const original = await importOriginal<typeof os>();
  return {
    ...original,
    homedir: () => mockHomeDir,
  };
});

import { trustInNss, DevCert } from "@devcontainer-dev-certs/shared";
import { runProcess } from "@devcontainer-dev-certs/shared/src/platform/processUtil";

const mockedRunProcess = vi.mocked(runProcess);

/** A real self-signed CN=localhost certificate — `nicknameFor` has to parse
 *  it to derive the per-cert NSS nickname. */
const REAL_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIDCTCCAfGgAwIBAgIUKqotkm31fbIEbOVcgrem0favrgQwDQYJKoZIhvcNAQEL\n" +
  "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyODAwMDM1OFoXDTM2MDgy\n" +
  "NTAwMDM1OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n" +
  "AAOCAQ8AMIIBCgKCAQEAjgGYX2B2v2F5mSgDK2skLTZ7WtkYEJXZ/dD3i4Io5ZuQ\n" +
  "5z4nt6VPSnCZFe8jBcDqcgdnCWUOG8yo7BP0pMQHMNRcqmyfMssIKWenPSPWU3U1\n" +
  "qMkah8hJbzQkuPlL88yBRDGlHI5ioE6YJKkvwaXBEpaj7xwL0IeOg7ODBz/C6lev\n" +
  "KGqfh8180tJ2/SJc6Hpgi0aaWFmkaYyB2/xZnxGTOaXlYtaU1WLVHSG0pJUdYEAm\n" +
  "m8S/oaofwPNEG/GStb+X5NVQKxQS2ZhsPcrv55EoZ43ukRwvUCeE1jN0xAVx9KO6\n" +
  "1PzYWxGwrneCv45VV+698LstLLn9tWL0FAe0MWxfcwIDAQABo1MwUTAdBgNVHQ4E\n" +
  "FgQUszuVse2bqDyPBDxDgwodnoWFiSowHwYDVR0jBBgwFoAUszuVse2bqDyPBDxD\n" +
  "gwodnoWFiSowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAd8fg\n" +
  "cVxi0bb27kpCjCBBkWGJkfu2SpY8D345PPvsQfxEoaBmvmPSo+V0uO5vPM6VQkMb\n" +
  "nwOyGytTYM+uVWADA3YJ+gYpToRfWE+06hKh2ziCDves8rObymLHApFosU0ulT35\n" +
  "HWw7S1Sv68k4Wqh7Q7neaYdKGjXWIpMbQ/aDUkUSRYYdmCyidmxAJFi71ROmkl0N\n" +
  "SutU65eZyiU8Rh6GSn1u3iPn+DHtcI/3npplew/kXUSliw4gpI7lipD31uBHVJc+\n" +
  "k8ge6yTGRi5QppCpiSYcpv0MJ1+DdaadFkYjOV4DPXid9xeJ7ZwQX2rK6Zbkj36Z\n" +
  "dW1E/BkFPJeKGPofjA==\n" +
  "-----END CERTIFICATE-----\n";


function makeNssDb(...segs: string[]): string {
  const dir = path.join(mockHomeDir, ...segs);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "cert9.db"), "");
  return dir;
}

function whichOk(): void {
  mockedRunProcess.mockResolvedValueOnce({
    exitCode: 0,
    stdout: "/usr/bin/certutil\n",
    stderr: "",
    truncated: false,
  });
}

function certutilOk(times: number): void {
  for (let i = 0; i < times; i++) {
    mockedRunProcess.mockResolvedValueOnce({
      exitCode: 0,
      stdout: "",
      stderr: "",
      truncated: false,
    });
  }
}

describe("trustInNss", () => {
  let tmpDir: string;
  let pemPath: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "devcerts-nss-test-"));
    mockHomeDir = tmpDir;
    pemPath = path.join(tmpDir, "test-cert.pem");
    fs.writeFileSync(
      pemPath,
      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns failure when certutil is not installed", async () => {
    mockedRunProcess.mockResolvedValue({
      exitCode: 1,
      stdout: "",
      stderr: "which: no certutil in PATH",
      truncated: false,
    });

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("certutil is not installed");
  });

  it("returns failure when no NSS databases are found", async () => {
    // certutil exists but no browser profiles in mockHomeDir
    mockedRunProcess.mockResolvedValue({
      exitCode: 0,
      stdout: "/usr/bin/certutil\n",
      stderr: "",
      truncated: false,
    });

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("No browser NSS databases found");
  });

  it("trusts in native Chromium NSS database when present", async () => {
    const nssDir = makeNssDb(".pki", "nssdb");
    whichOk();
    certutilOk(2); // -D then -A

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium");

    const addCall = mockedRunProcess.mock.calls.find(
      (call) => call[0] === "certutil" && call[1].includes("-A")
    );
    expect(addCall).toBeDefined();
    expect(addCall![1]).toContain("P,,");
    expect(addCall![1]).toContain(pemPath);
    expect(addCall![1]).toContain(`sql:${nssDir}`);
  });

  it("trusts in native Firefox profile NSS databases when present", async () => {
    makeNssDb(".mozilla", "firefox", "abc123.default");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (abc123.default)");
  });

  it("trusts in Snap Firefox profile NSS databases when present", async () => {
    makeNssDb("snap", "firefox", "common", ".mozilla", "firefox", "snap.default");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (Snap) (snap.default)");
  });

  it("trusts in Flatpak Firefox profile NSS databases when present", async () => {
    makeNssDb(
      ".var",
      "app",
      "org.mozilla.firefox",
      ".mozilla",
      "firefox",
      "fp.default"
    );
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Firefox (Flatpak) (fp.default)");
  });

  it("trusts in Snap Chromium NSS database when present", async () => {
    makeNssDb("snap", "chromium", "common", ".pki", "nssdb");
    whichOk();
    certutilOk(2);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium (Snap)");
  });

  it("trusts in Flatpak Chromium-family NSS databases when present", async () => {
    makeNssDb(".var", "app", "com.google.Chrome", ".pki", "nssdb");
    makeNssDb(".var", "app", "com.brave.Browser", ".pki", "nssdb");
    whichOk();
    certutilOk(4); // 2 dbs × (-D, -A)

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Chrome (Flatpak)");
    expect(result.message).toContain("Brave (Flatpak)");
  });

  it("trusts in Firefox forks (LibreWolf, Waterfox, Floorp, ESR) when present", async () => {
    makeNssDb(".mozilla", "firefox-esr", "esr.default");
    makeNssDb(".librewolf", "lw.default");
    makeNssDb(".waterfox", "wf.default");
    makeNssDb(".floorp", "fl.default");
    whichOk();
    certutilOk(8);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Firefox ESR (esr.default)");
    expect(result.message).toContain("LibreWolf (lw.default)");
    expect(result.message).toContain("Waterfox (wf.default)");
    expect(result.message).toContain("Floorp (fl.default)");
  });

  it("reports failure per-database when certutil -A fails", async () => {
    makeNssDb(".mozilla", "firefox", "test.profile");
    whichOk();
    mockedRunProcess
      .mockResolvedValueOnce({ exitCode: 0, stdout: "", stderr: "", truncated: false }) // -D
      .mockResolvedValueOnce({
        exitCode: 1,
        stdout: "",
        stderr: "SEC_ERROR_BAD_DATABASE",
        truncated: false,
      }); // -A fails

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("Firefox (test.profile): failed");
    expect(result.message).toContain("SEC_ERROR_BAD_DATABASE");
  });

  it("removes existing cert before adding for idempotency", async () => {
    makeNssDb(".mozilla", "firefox", "idempotent.profile");
    whichOk();
    certutilOk(2);

    await trustInNss(pemPath);

    const deleteCall = mockedRunProcess.mock.calls[1];
    expect(deleteCall[0]).toBe("certutil");
    expect(deleteCall[1]).toContain("-D");
    expect(deleteCall[1]).toContain("Dev Container Dev Cert");

    const addCall = mockedRunProcess.mock.calls[2];
    expect(addCall[0]).toBe("certutil");
    expect(addCall[1]).toContain("-A");
  });

  // The cert is a self-signed end entity (cA=FALSE), so `P` (CERTDB_TRUSTED,
  // "trusted peer") is the correct NSS encoding — except in Firefox, which
  // empirically ignores `P` for server certs. `dotnet dev-certs https
  // --trust` makes exactly this split, and Microsoft validated it against
  // real browsers. A blanket flag is wrong for one family either way.
  it("uses trusted-peer (P,,) for Chromium databases", async () => {
    makeNssDb(".pki", "nssdb");
    whichOk();
    certutilOk(2);

    await trustInNss(pemPath);

    const addCall = mockedRunProcess.mock.calls[2];
    expect(addCall[1]).toContain("-A");
    expect(addCall[1][addCall[1].indexOf("-t") + 1]).toBe("P,,");
  });

  it("uses trusted-CA (C,,) for Firefox profiles", async () => {
    makeNssDb(".mozilla", "firefox", "flags.profile");
    whichOk();
    certutilOk(2);

    await trustInNss(pemPath);

    const addCall = mockedRunProcess.mock.calls[2];
    expect(addCall[1]).toContain("-A");
    expect(addCall[1][addCall[1].indexOf("-t") + 1]).toBe("C,,");
  });

  it("picks the flag per database when both families are present", async () => {
    makeNssDb(".pki", "nssdb");
    makeNssDb(".mozilla", "firefox", "both.default");
    whichOk();
    certutilOk(4);

    await trustInNss(pemPath);

    // getNssTargets is ordered Chromium-family first, so calls 2 and 4 are
    // the two `-A` invocations (each preceded by its idempotency delete).
    const chromiumAdd = mockedRunProcess.mock.calls[2];
    const firefoxAdd = mockedRunProcess.mock.calls[4];
    expect(chromiumAdd[1][chromiumAdd[1].indexOf("-t") + 1]).toBe("P,,");
    expect(firefoxAdd[1][firefoxAdd[1].indexOf("-t") + 1]).toBe("C,,");
  });

  it("handles native Chromium and Firefox in a single call", async () => {
    makeNssDb(".pki", "nssdb");
    makeNssDb(".mozilla", "firefox", "multi.default");
    whichOk();
    certutilOk(4);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    expect(result.message).toContain("Trusted in: Chromium, Firefox (multi.default)");
  });

  it("skips Firefox roots silently when no profile has cert9.db", async () => {
    // Profile dir exists but no cert9.db inside — counts as not-yet-initialized
    const noCertProfile = path.join(
      mockHomeDir,
      ".mozilla",
      "firefox",
      "empty.profile"
    );
    fs.mkdirSync(noCertProfile, { recursive: true });
    whichOk();

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(false);
    expect(result.message).toContain("No browser NSS databases found");
  });

  it("combines trusted databases into a single comma-separated entry", async () => {
    makeNssDb(".pki", "nssdb");
    makeNssDb("snap", "firefox", "common", ".mozilla", "firefox", "p.default");
    whichOk();
    certutilOk(4);

    const result = await trustInNss(pemPath);

    expect(result.success).toBe(true);
    // Exactly one "Trusted in:" prefix — failures (none here) would be appended
    // separately after a semicolon.
    expect(result.message.match(/Trusted in:/g)?.length).toBe(1);
    expect(result.message).toBe(
      "Trusted in: Chromium, Firefox (Snap) (p.default)"
    );
  });

  it("names each certificate by thumbprint so two dev certs can coexist", async () => {
    // NSS nicknames are unique per database. A shared nickname made every
    // `trustInNss` call evict the previously-trusted cert — so the host's
    // generated cert and a container-pushed one could never both be trusted
    // in browsers, even though the OpenSSL trust dir is deliberately
    // additive for exactly that reason.
    const realPemPath = path.join(tmpDir, "real-cert.pem");
    fs.writeFileSync(realPemPath, REAL_PEM);
    const expectedNickname = `Dev Container Dev Cert (${new DevCert(REAL_PEM).thumbprintSha1})`;

    makeNssDb(".mozilla", "firefox", "thumbprint.profile");
    whichOk();
    certutilOk(3);

    await trustInNss(realPemPath);

    // 1: delete the pre-thumbprint nickname (upgrade cleanup), 2: delete our
    // own nickname (idempotency), 3: add under our own nickname.
    const legacyDelete = mockedRunProcess.mock.calls[1];
    expect(legacyDelete[1]).toContain("-D");
    expect(legacyDelete[1]).toContain("Dev Container Dev Cert");

    const selfDelete = mockedRunProcess.mock.calls[2];
    expect(selfDelete[1]).toContain("-D");
    expect(selfDelete[1]).toContain(expectedNickname);

    const addCall = mockedRunProcess.mock.calls[3];
    expect(addCall[1]).toContain("-A");
    expect(addCall[1]).toContain(expectedNickname);
    expect(addCall[1]).toContain(realPemPath);
  });
});
