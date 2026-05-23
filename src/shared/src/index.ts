export { initLogger, log, revealLogger } from "./logger";
export type {
  CertMaterial,
  CertKind,
  CertMaterialV2,
  CertBundle,
  CertMaterialV3,
  CertBundleV3,
  DestFormat,
} from "./types";
export { DOTNET_DEV_CERT_NAME } from "./types";
export {
  getDotNetStorePath,
  getDotNetRootStorePath,
  getOpenSslTrustDir,
  getPfxFileName,
  getPemFileName,
  getPemFileNameForUser,
} from "./paths";
export { isValidCertName, assertValidCertName } from "./certName";

// Cert primitives — shared between host (UI) and workspace (remote)
// extensions. The host generates/exports as before; the workspace uses the
// same loader / classifier / validator surfaces when scanning for a
// container-side dev cert to push back to the host.
export { DevCert, DevKey } from "./cert/types";
export type { DevKeyAlgorithm } from "./cert/types";
export {
  RSA_KEY_SIZE,
  VALIDITY_DAYS,
  ASPNET_HTTPS_OID,
  ASPNET_HTTPS_OID_FRIENDLY_NAME,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
} from "./cert/properties";
export { buildPfx, parsePfx } from "./cert/pfx";
export type { BuildPfxOptions, ParsedPfx } from "./cert/pfx";
export { loadPfx, loadPemPair } from "./cert/loader";
export type { LoadedCert } from "./cert/loader";
export {
  isValidDevCert,
  getCertificateVersion,
  computeThumbprint,
  validateLocalSans,
  collectSanEntries,
} from "./cert/validation";
export type {
  NonLocalSanEntry,
  SanLocalValidationResult,
} from "./cert/validation";
export {
  classifyCandidate,
  selectBestDevCert,
  extractThumbprintHintFromFilename,
} from "./cert/classify";
export type {
  ClassifiedCandidate,
  CandidateMetadata,
  CandidateInput,
  ClassifyOptions,
  SkipReport,
  SkipReasonCode,
  SelectionReport,
  SelectBestOptions,
  UsableDevCert,
} from "./cert/classify";
