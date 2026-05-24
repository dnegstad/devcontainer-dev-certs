// Re-export shim: the canonical home for these constants is now
// `@devcontainer-dev-certs/shared`. Keeping this thin re-export so existing
// `./cert/properties` imports across the UI extension (and its test suite)
// keep resolving without a sweeping rename.
export {
  RSA_KEY_SIZE,
  VALIDITY_DAYS,
  ASPNET_HTTPS_OID,
  ASPNET_HTTPS_OID_FRIENDLY_NAME,
  CURRENT_CERTIFICATE_VERSION,
  MINIMUM_CERTIFICATE_VERSION,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
} from "@devcontainer-dev-certs/shared";
