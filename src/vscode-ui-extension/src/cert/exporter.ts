// Re-export shim: the canonical home for the exporter helpers is now
// `@devcontainer-dev-certs/shared`. Keeping this thin re-export so existing
// `./cert/exporter` imports across the UI extension (and its test suite)
// keep resolving without a sweeping rename.
export {
  exportPfx,
  exportPem,
  exportRootPfx,
  exportLoadedCert,
  certToPem,
  keyToPem,
  certToDer,
} from "@devcontainer-dev-certs/shared";
export type { ExportedLoadedCert } from "@devcontainer-dev-certs/shared";
