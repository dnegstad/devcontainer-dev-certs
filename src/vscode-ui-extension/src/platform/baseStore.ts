// Re-export shim: the canonical home for the localized platform classifier
// wrappers and `BaseCertificateStore` is now in
// `@devcontainer-dev-certs/shared`. Imports go through the submodule path
// (rather than the barrel) because the barrel aliases the platform-flavored
// `classifyCandidate` / `selectBestDevCert` to disambiguate from the pure
// classifier; existing tests and call sites expect the unaliased names.
export {
  BaseCertificateStore,
  classifyCandidate,
  selectBestDevCert,
  extractThumbprintHintFromFilename,
} from "@devcontainer-dev-certs/shared/src/platform/baseStore";
export type {
  ClassifiedCandidate,
  CandidateInput,
  CandidateMetadata,
  UsableDevCert,
  ClassifyOptions,
} from "@devcontainer-dev-certs/shared/src/platform/baseStore";
