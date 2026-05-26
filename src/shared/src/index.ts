export { log, revealLogger, setLogSink } from "./logger";
export type { LogSink } from "./logger";
export { identityLocalizer } from "./localizer";
export type { Localizer } from "./localizer";
export type {
  CertMaterial,
  CertKind,
  CertMaterialV2,
  CertBundle,
  CertMaterialV3,
  CertBundleV3,
  DefaultKestrelCertSelection,
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
  getKestrelDefaultCertPath,
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
export { generateCertificate } from "./cert/generator";
export type { GenerateAlgorithm, GeneratedCert } from "./cert/generator";
export {
  exportPfx,
  exportPem,
  exportRootPfx,
  exportLoadedCert,
  certToPem,
  keyToPem,
  certToDer,
} from "./cert/exporter";
export type { ExportedLoadedCert } from "./cert/exporter";
export { CertManager } from "./cert/manager";
export type { CertManagerOptions } from "./cert/manager";

// Platform trust-store layer — orchestrates per-OS dev-cert storage and
// trust. Lives in shared so a future host CLI can share the implementation
// with the VS Code extension.
export {
  createPlatformStore,
} from "./platform/types";
export type {
  PlatformCertificateStore,
  CertificateStatus,
  CreatePlatformStoreOptions,
  BaseStoreOptions,
  LinuxNssTrustReporter,
} from "./platform/types";
export {
  BaseCertificateStore,
  classifyCandidate as classifyPlatformCandidate,
  selectBestDevCert as selectBestPlatformDevCert,
} from "./platform/baseStore";
export type { ClassifyOptions as PlatformClassifyOptions } from "./platform/baseStore";
export { LinuxCertificateStore } from "./platform/linuxStore";
export type { LinuxCertificateStoreOptions } from "./platform/linuxStore";
export { MacCertificateStore } from "./platform/macStore";
export {
  WindowsCertificateStore,
} from "./platform/windowsStore";
export type {
  WindowsStoreLocation,
  PsCandidate,
  PsSkipped,
  PsSkipReason,
  PsEnumeration,
} from "./platform/windowsStore";
export { trustInNss } from "./platform/nssTrust";
export type { NssTrustResult } from "./platform/nssTrust";
export { runProcess, resolveSafeExecPath } from "./platform/processUtil";
export type {
  ProcessResult,
  ResolveSafeExecPathOptions,
} from "./platform/processUtil";

// Backend abstraction — selectable cert-generator backends shared by the
// host CLI (`ddc`) and the VS Code host extension. Lets both consumers
// pick between the bundled native generator, the `dotnet dev-certs https`
// pass-through, and (future) an Aspire-aware variant without each
// having to reimplement availability detection / selection logic.
export { NativeBackend } from "./backends/native";
export { DotnetBackend } from "./backends/dotnet";
export { selectBackend, describeAutoBackend } from "./backends/select";
export type {
  Backend,
  BackendKind,
  BackendMode,
  GenerateOptions,
  GenerateResult,
} from "./backends/types";
