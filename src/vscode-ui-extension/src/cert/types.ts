// Re-export shim: the canonical home for DevCert / DevKey is now
// `@devcontainer-dev-certs/shared`. Keeping this thin re-export so existing
// `./cert/types` imports across the UI extension (and its test suite) keep
// resolving without a sweeping rename.
export { DevCert, DevKey } from "@devcontainer-dev-certs/shared";
export type { DevKeyAlgorithm } from "@devcontainer-dev-certs/shared";
