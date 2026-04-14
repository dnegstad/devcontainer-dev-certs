import { describe, it, expect, vi, beforeEach } from "vitest";
import * as forge from "node-forge";
import {
  PlatformCertificateStore,
  CertificateStatus,
} from "../src/platform/types";
import { generateCertificate } from "../src/cert/generator";
import { VALIDITY_DAYS } from "../src/cert/properties";

// We need to mock createPlatformStore so the CertManager uses our fake store.
// Import the module under test after mocking.
vi.mock("../src/platform/types", async (importOriginal) => {
  const original =
    (await importOriginal()) as typeof import("../src/platform/types");
  return {
    ...original,
    createPlatformStore: vi.fn(),
  };
});

import { CertManager } from "../src/cert/manager";
import { createPlatformStore } from "../src/platform/types";

const mockedCreateStore = vi.mocked(createPlatformStore);

function makeTestCert() {
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
      const checkStatus = vi.fn()
        // First call: nothing exists
        .mockResolvedValueOnce({
          exists: false,
          isTrusted: false,
          thumbprint: null,
          notBefore: null,
          notAfter: null,
          version: -1,
        })
        // After generate, exists but not trusted
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
      const existing = makeTestCert();
      const checkStatus = vi.fn()
        // First call: exists but not trusted
        .mockResolvedValueOnce({
          exists: true,
          isTrusted: false,
          thumbprint: existing.thumbprint,
          notBefore: new Date().toISOString(),
          notAfter: new Date().toISOString(),
          version: 6,
        })
        // Recheck: still not trusted
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
      const existing = makeTestCert();
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
      await expect(
        manager.exportCert("pfx", "/tmp/out")
      ).rejects.toThrow("No dev certificate found");
    });

    it("exports after generate without extra store lookup", async () => {
      const manager = new CertManager();
      await manager.generate();

      // exportCert shouldn't need to call findExistingDevCert since
      // we just generated a cert
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
});
