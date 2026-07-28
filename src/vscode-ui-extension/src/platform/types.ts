// Re-export shim: the canonical home for the platform store types and the
// `createPlatformStore` factory is now `@devcontainer-dev-certs/shared`.
// Keeping this thin re-export so existing `./platform/types` imports across
// the UI extension and its test suite keep resolving without a rename.
export type {
  LinuxNssTrustReporter,
  BaseStoreOptions,
  CreatePlatformStoreOptions,
  CertificateStatus,
  PlatformCertificateStore,
} from "@devcontainer-dev-certs/shared";
export { createPlatformStore } from "@devcontainer-dev-certs/shared";
