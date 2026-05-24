import { describe, it, expect, vi, beforeEach } from "vitest";
import type * as PlatformTypes from "../src/platform/types";
import {
  type PlatformCertificateStore,
  type CertificateStatus,
} from "../src/platform/types";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

// Mock createPlatformStore so the CertManager uses our fake store.
vi.mock("../src/platform/types", async (importOriginal) => {
  const original = await importOriginal<typeof PlatformTypes>();
  return {
    ...original,
    createPlatformStore: vi.fn(),
  };
});

import { CertManager } from "../src/cert/manager";
import { createPlatformStore } from "../src/platform/types";

const mockedCreateStore = vi.mocked(createPlatformStore);

async function makeTestCert(): ReturnType<typeof generateCertificate> {
  const now = new Date();
  const expiry = new Date(
    now.getTime() + VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  return generateCertificate(now, expiry);
}

function makeFakeStore(
  overrides: Partial<PlatformCertificateStore> = {}
): PlatformCertificateStore {
  return {
    findExistingDevCert: vi.fn().mockResolvedValue(null),
    saveCertificate: vi.fn().mockResolvedValue(undefined),
    trustCertificate: vi.fn().mockResolvedValue(undefined),
    removeCertificates: vi.fn().mockResolvedValue(undefined),
    checkStatus: vi.fn().mockResolvedValue({
      exists: false,
      isTrusted: false,
      thumbprint: null,
      notBefore: null,
      notAfter: null,
      version: -1,
    } satisfies CertificateStatus),
    ...overrides,
  };
}

describe("CertManager", () => {
  let store: PlatformCertificateStore;

  beforeEach(() => {
    vi.clearAllMocks();
    store = makeFakeStore();
    mockedCreateStore.mockResolvedValue(store);
  });

  describe("generate", () => {
    it("saves a new cert to the store", async () => {
      const manager = new CertManager();
      await manager.generate();
      expect(store.saveCertificate).toHaveBeenCalledOnce();
    });

    it("removes existing certs when force is true", async () => {
      const manager = new CertManager();
      await manager.generate(true);
      expect(store.removeCertificates).toHaveBeenCalledOnce();
      expect(store.saveCertificate).toHaveBeenCalledOnce();
    });

    it("does not remove existing certs when force is false", async () => {
      const manager = new CertManager();
      await manager.generate(false);
      expect(store.removeCertificates).not.toHaveBeenCalled();
    });
  });

  describe("trust", () => {
    it("generates and trusts if no cert exists", async () => {
      const checkStatus = vi
        .fn()
        .mockResolvedValueOnce({
          exists: false,
          isTrusted: false,
          thumbprint: null,
          notBefore: null,
          notAfter: null,
          version: -1,
        })
        .mockResolvedValueOnce({
          exists: true,
          isTrusted: false,
          thumbprint: "ABC123",
          notBefore: new Date().toISOString(),
          notAfter: new Date().toISOString(),
          version: 6,
        });

      store = makeFakeStore({ checkStatus });
      mockedCreateStore.mockResolvedValue(store);

      const manager = new CertManager();
      await manager.trust();

      expect(store.saveCertificate).toHaveBeenCalledOnce();
      expect(store.trustCertificate).toHaveBeenCalledOnce();
    });

    it("skips generation if cert already exists but trusts it", async () => {
      const existing = await makeTestCert();
      const checkStatus = vi
        .fn()
        .mockResolvedValueOnce({
          exists: true,
          isTrusted: false,
          thumbprint: existing.thumbprint,
          notBefore: new Date().toISOString(),
          notAfter: new Date().toISOString(),
          version: 6,
        })
        .mockResolvedValueOnce({
          exists: true,
          isTrusted: false,
          thumbprint: existing.thumbprint,
          notBefore: new Date().toISOString(),
          notAfter: new Date().toISOString(),
          version: 6,
        });

      store = makeFakeStore({
        checkStatus,
        findExistingDevCert: vi.fn().mockResolvedValue(existing),
      });
      mockedCreateStore.mockResolvedValue(store);

      const manager = new CertManager();
      await manager.trust();

      expect(store.saveCertificate).not.toHaveBeenCalled();
      expect(store.trustCertificate).toHaveBeenCalledOnce();
    });

    it("skips both generation and trust if cert exists and is already trusted", async () => {
      const existing = await makeTestCert();
      const checkStatus = vi.fn().mockResolvedValue({
        exists: true,
        isTrusted: true,
        thumbprint: existing.thumbprint,
        notBefore: new Date().toISOString(),
        notAfter: new Date().toISOString(),
        version: 6,
      });

      store = makeFakeStore({
        checkStatus,
        findExistingDevCert: vi.fn().mockResolvedValue(existing),
      });
      mockedCreateStore.mockResolvedValue(store);

      const manager = new CertManager();
      await manager.trust();

      expect(store.saveCertificate).not.toHaveBeenCalled();
      expect(store.trustCertificate).not.toHaveBeenCalled();
    });
  });

  describe("check", () => {
    it("delegates to the platform store", async () => {
      const expected: CertificateStatus = {
        exists: true,
        isTrusted: true,
        thumbprint: "AABBCCDD",
        notBefore: "2025-01-01",
        notAfter: "2026-01-01",
        version: 6,
      };
      store = makeFakeStore({
        checkStatus: vi.fn().mockResolvedValue(expected),
      });
      mockedCreateStore.mockResolvedValue(store);

      const manager = new CertManager();
      const result = await manager.check();
      expect(result).toEqual(expected);
    });
  });

  describe("clean", () => {
    it("delegates to the platform store", async () => {
      const manager = new CertManager();
      await manager.clean();
      expect(store.removeCertificates).toHaveBeenCalledOnce();
    });
  });

  describe("exportCert", () => {
    it("throws if no cert is loaded and none in store", async () => {
      const manager = new CertManager();
      await expect(manager.exportCert("pfx", "/tmp/out")).rejects.toThrow(
        "No dev certificate found"
      );
    });

    it("exports after generate without extra store lookup", async () => {
      const manager = new CertManager();
      await manager.generate();

      const dir = `/tmp/devcerts-test-export-${Date.now()}`;
      try {
        await manager.exportCert("pfx", dir);
        expect(store.findExistingDevCert).not.toHaveBeenCalled();
      } finally {
        const fs = await import("fs");
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // Pins the design contract from issue #63: trust for a container-pushed
  // cert MUST flow through the same `store.trustCertificate(cert)` hook
  // the host-generation flow uses. That hook is where the per-platform
  // trust surfaces live — on Linux it does `trustInDotNetRootStore` +
  // `trustViaOpenSsl` + `trustInNssBrowsers` (NSS browser trust!), on
  // macOS it sets login keychain trust policy, on Windows it adds to
  // CurrentUser/Root. Going through `trustCertificate` is what keeps
  // "trusted on the host" mean the same thing regardless of where the
  // cert originated. The save/`my/` step is INTENTIONALLY skipped — the
  // host never holds the private key in this flow.
  describe("trustExternalCertificate (reverse-sync)", () => {
    it("invokes the same store.trustCertificate hook as the generation flow", async () => {
      const generated = await makeTestCert();
      const manager = new CertManager();
      await manager.trustExternalCertificate(generated.cert);

      expect(store.trustCertificate).toHaveBeenCalledTimes(1);
      expect(store.trustCertificate).toHaveBeenCalledWith(generated.cert);
    });

    it("does NOT call saveCertificate (no private key sync, no my/ write)", async () => {
      const generated = await makeTestCert();
      const manager = new CertManager();
      await manager.trustExternalCertificate(generated.cert);

      expect(store.saveCertificate).not.toHaveBeenCalled();
    });

    it("does not consult findExistingDevCert — the caller supplied the cert", async () => {
      const generated = await makeTestCert();
      const manager = new CertManager();
      await manager.trustExternalCertificate(generated.cert);

      expect(store.findExistingDevCert).not.toHaveBeenCalled();
    });
  });
});
