import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
} from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type * as Shared from "@devcontainer-dev-certs/shared";

vi.mock("@devcontainer-dev-certs/shared", async () => {
  const actual = await vi.importActual<typeof Shared>(
    "@devcontainer-dev-certs/shared"
  );
  return { ...actual, selectBackend: vi.fn() };
});

import { selectBackend } from "@devcontainer-dev-certs/shared";
import { runGenerate } from "../src/commands/generate";

const mockedSelectBackend = vi.mocked(selectBackend);
const cleanupDirs: string[] = [];

function fakeBackend(): Shared.Backend {
  return {
    kind: "native",
    isAvailable: () => Promise.resolve(true),
    generate: vi.fn(async (opts: Shared.GenerateOptions) => ({
      pfxPath: path.join(opts.outDir, "aspnetcore-dev.pfx"),
      pemPath: path.join(opts.outDir, "aspnetcore-dev.pem"),
      pemKeyPath: path.join(opts.outDir, "aspnetcore-dev.key"),
      thumbprint: "ABCDEF1234567890",
      trusted: !opts.noTrust,
      backendUsed: "native",
    })),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  mockedSelectBackend.mockResolvedValue(fakeBackend());
});

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of cleanupDirs) fs.rmSync(dir, { recursive: true, force: true });
  cleanupDirs.length = 0;
});

describe("dcdc generate --no-trust propagation to bundle.json", () => {
  it("emits trustInContainer:false when --no-trust is passed", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-gen-notrust-"));
    cleanupDirs.push(outDir);

    await runGenerate({
      outDir,
      backend: "native",
      noTrust: true,
    });

    const bundle = JSON.parse(
      fs.readFileSync(path.join(outDir, "bundle.json"), "utf-8")
    ) as Record<string, unknown>;
    const cert = (bundle.certs as Array<Record<string, unknown>>)[0];
    expect(cert.trustInContainer).toBe(false);
  });

  it("emits trustInContainer:true when --no-trust is NOT passed", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-gen-trust-"));
    cleanupDirs.push(outDir);

    await runGenerate({
      outDir,
      backend: "native",
    });

    const bundle = JSON.parse(
      fs.readFileSync(path.join(outDir, "bundle.json"), "utf-8")
    ) as Record<string, unknown>;
    const cert = (bundle.certs as Array<Record<string, unknown>>)[0];
    expect(cert.trustInContainer).toBe(true);
  });

  it("forwards a stderr NSS reporter to the backend (so failures don't pass silently)", async () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "dcdc-gen-reporter-"));
    cleanupDirs.push(outDir);
    const backend = fakeBackend();
    mockedSelectBackend.mockResolvedValueOnce(backend);

    await runGenerate({
      outDir,
      backend: "native",
    });

    const generateMock = vi.mocked(backend.generate);
    expect(generateMock).toHaveBeenCalledTimes(1);
    const opts = generateMock.mock.calls[0][0];
    expect(opts.linuxNssTrustReporter).toBeInstanceOf(Function);
  });
});
