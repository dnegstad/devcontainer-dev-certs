/**
 * Certificate properties matching the ASP.NET Core HTTPS development certificate format.
 * These values must stay in sync with dotnet dev-certs to produce functionally identical certs.
 */

/** RSA key size in bits. */
export const RSA_KEY_SIZE = 2048;

/** Certificate validity in days from generation. */
export const VALIDITY_DAYS = 365;

/**
 * OID that identifies a certificate as an ASP.NET Core HTTPS development certificate.
 * Microsoft private arc: 1.3.6.1.4.1.311 = Microsoft, 84.1.1 = ASP.NET HTTPS dev cert.
 */
export const ASPNET_HTTPS_OID = "1.3.6.1.4.1.311.84.1.1";

export const ASPNET_HTTPS_OID_FRIENDLY_NAME =
  "ASP.NET Core HTTPS development certificate";

/**
 * Current version of the dev cert format. Stored as a single byte in the custom OID extension.
 * Version 6 was introduced in .NET SDK 10.0.102 / runtime 10.0.2.
 */
export const CURRENT_CERTIFICATE_VERSION = 6;

/**
 * Minimum version accepted by non-interactive consumers.
 * Version 4 was introduced in .NET SDK 10.0.100 / runtime 10.0.0.
 */
export const MINIMUM_CERTIFICATE_VERSION = 4;

/** DNS names for Subject Alternative Names. */
export const SAN_DNS_NAMES = [
  "localhost",
  "*.dev.localhost",
  "*.dev.internal",
  "host.docker.internal",
  "host.containers.internal",
];

/** IP addresses for Subject Alternative Names. */
export const SAN_IP_ADDRESSES = [
  "127.0.0.1", // IPv4 loopback
  "::1", // IPv6 loopback
];
