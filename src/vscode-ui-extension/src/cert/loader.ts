// Re-export shim: the canonical home for loadPfx / loadPemPair / LoadedCert
// is now `@devcontainer-dev-certs/shared`. Keeping this thin re-export so
// existing `./cert/loader` imports across the UI extension (and its test
// suite) keep resolving without a sweeping rename.
export { loadPfx, loadPemPair } from "@devcontainer-dev-certs/shared";
export type { LoadedCert } from "@devcontainer-dev-certs/shared";
