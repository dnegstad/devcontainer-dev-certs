import { describe, it, expect, vi, beforeEach } from "vitest";
import type * as PlatformTypes from "@devcontainer-dev-certs/shared/src/platform/types";
import {
  generateCertificate,
  VALIDITY_DAYS,
  CertManager,
} from "@devcontainer-dev-certs/shared";
import type {
  PlatformCertificateStore,
  CertificateStatus,
} from "@devcontainer-dev-certs/shared";

// Mock createPlatformStore so the CertManager uses our fake store. The
// CertManager now lives in `@devcontainer-dev-certs/shared` and imports
// `createPlatformStore` from the sibling `../platform/types`; the mock has
// to target that exact module path so the shared CertManager sees it too.
vi.mock("@devcontainer-dev-certs/shared/src/platform/types", async (importOriginal) => {
  const original = await importOriginal<typeof PlatformTypes>();
  return {
    ...original,
    createPlatformStore: vi.fn(),
  };
});

import { createPlatformStore } from "@devcontainer-dev-certs/shared/src/platform/types";

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
    // Default to NOT trusted so trustExternalCertificate's verify-on-disk
    // short-circuit doesn't accidentally skip the trustCertificate call
    // in tests that pre-date that check. Tests that want to assert the
    // short-circuit fires override this to true.
    isCertTrusted: vi.fn().mockResolvedValue(false),
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

    it("reloads from the store when the cached cert no longer matches (external replacement)", async () => {
      // Regression: with cert A cached in memory and the store entry
      // externally replaced by cert B, trust() used to keep A (the
      // reload only ran when NOTHING was cached) and re-trust the
      // orphaned A while B stayed untrusted — a later export would
      // then serve untrusted B.
      const certA = await makeTestCert();
      const certB = await makeTestCert();
      const notTrusted = (thumbprint: string) => ({
        exists: true,
        isTrusted: false,
        thumbprint,
        notBefore: new Date().toISOString(),
        notAfter: new Date().toISOString(),
        version: 6,
      });
      const checkStatus = vi
        .fn()
        .mockResolvedValueOnce(notTrusted(certA.thumbprint)) // trust #1: status
        .mockResolvedValueOnce(notTrusted(certA.thumbprint)) // trust #1: recheck
        .mockResolvedValueOnce(notTrusted(certB.thumbprint)) // trust #2: store replaced
        .mockResolvedValueOnce(notTrusted(certB.thumbprint)); // trust #2: recheck
      const findExistingDevCert = vi
        .fn()
        .mockResolvedValueOnce(certA)
        .mockResolvedValueOnce(certB);

      store = makeFakeStore({ checkStatus, findExistingDevCert });
      mockedCreateStore.mockResolvedValue(store);

      const manager = new CertManager();
      await manager.trust(); // loads + trusts A
      await manager.trust(); // must reload and trust B, not the cached A

      expect(findExistingDevCert).toHaveBeenCalledTimes(2);
      const trusted = vi
        .mocked(store.trustCertificate)
        .mock.calls.map((call) => call[0]);
      expect(trusted[0]).toBe(certA.cert);
      expect(trusted[1]).toBe(certB.cert);
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

    it("verifies on-disk trust state via store.isCertTrusted before invoking trustCertificate", async () => {
      const generated = await makeTestCert();
      const manager = new CertManager();
      await manager.trustExternalCertificate(generated.cert);

      expect(store.isCertTrusted).toHaveBeenCalledTimes(1);
      expect(store.isCertTrusted).toHaveBeenCalledWith(generated.cert);
    });

    it("short-circuits when isCertTrusted returns true — no redundant platform trust call", async () => {
      // Idempotency contract: repeated trust calls for an already-
      // trusted cert must NOT re-invoke the platform trust step. On
      // macOS in particular, `security add-trusted-cert` is not a
      // true no-op for an already-trusted cert and can re-prompt for
      // the keychain password; the manager guards against that here.
      const generated = await makeTestCert();
      store = makeFakeStore({
        isCertTrusted: vi.fn().mockResolvedValue(true),
      });
      mockedCreateStore.mockResolvedValue(store);
      const manager = new CertManager();
      await manager.trustExternalCertificate(generated.cert);

      expect(store.isCertTrusted).toHaveBeenCalledTimes(1);
      expect(store.trustCertificate).not.toHaveBeenCalled();
    });
  });
});
