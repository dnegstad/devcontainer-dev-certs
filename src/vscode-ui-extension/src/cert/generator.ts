// Re-export shim: the canonical home for `generateCertificate` is now
// `@devcontainer-dev-certs/shared`. Keeping this thin re-export so existing
// `./cert/generator` imports across the UI extension (and its test suite)
// keep resolving without a sweeping rename. The validation helpers
// (`isValidDevCert`, `getCertificateVersion`, `computeThumbprint`) used to be
// defined alongside the generator and were re-exported here for historical
// reasons — we preserve those re-exports so existing call sites still resolve.
export {
  generateCertificate,
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
} from "@devcontainer-dev-certs/shared";
export type {
  GenerateAlgorithm,
  GeneratedCert,
} from "@devcontainer-dev-certs/shared";
