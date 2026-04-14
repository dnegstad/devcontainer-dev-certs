import * as forge from "node-forge";
import {
    ASPNET_HTTPS_OID,
    ASPNET_HTTPS_OID_FRIENDLY_NAME,
    CURRENT_CERTIFICATE_VERSION,
    MINIMUM_CERTIFICATE_VERSION,
    RSA_KEY_SIZE,
    SAN_DNS_NAMES,
    SAN_IP_ADDRESSES,
} from "./properties";

export interface GeneratedCert {
    cert: forge.pki.Certificate;
    key: forge.pki.rsa.PrivateKey;
    thumbprint: string;
}

/**
 * Generate a self-signed certificate matching the ASP.NET Core HTTPS dev cert format.
 */
export function generateCertificate(
    notBefore: Date,
    notAfter: Date
): GeneratedCert {
    // Generate RSA key pair
    const keyPair = forge.pki.rsa.generateKeyPair(RSA_KEY_SIZE);

    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = generateSerialNumber();
    cert.validity.notBefore = notBefore;
    cert.validity.notAfter = notAfter;

    // Subject and Issuer (self-signed, so they're the same)
    const attrs = [{ name: "commonName", value: "localhost" }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Compute Subject Key Identifier from public key
    const pubKeyDer = forge.asn1.toDer(
        forge.pki.publicKeyToAsn1(keyPair.publicKey)
    );
    const ski = forge.md.sha256.create().update(pubKeyDer.getBytes()).digest();
    const skiHex = ski.toHex();

    // Build extensions
    cert.setExtensions([
        // 1. Basic Constraints (critical) — not a CA
        {
            name: "basicConstraints",
            cA: false,
            critical: true,
        },
        // 2. Key Usage (critical) — KeyEncipherment | DigitalSignature
        {
            name: "keyUsage",
            critical: true,
            digitalSignature: true,
            keyEncipherment: true,
        },
        // 3. Enhanced Key Usage (critical) — Server Authentication
        {
            name: "extKeyUsage",
            critical: true,
            serverAuth: true,
        },
        // 4. Subject Alternative Names (critical)
        {
            name: "subjectAltName",
            critical: true,
            altNames: [
                ...SAN_DNS_NAMES.map((dns) => ({ type: 2 as const, value: dns })),
                ...SAN_IP_ADDRESSES.map((ip) => ({ type: 7 as const, ip })),
            ],
        },
        // 5. ASP.NET Core HTTPS Dev Cert marker (non-critical) — version byte
        {
            id: ASPNET_HTTPS_OID,
            critical: false,
            value: String.fromCharCode(CURRENT_CERTIFICATE_VERSION),
        },
        // 6. Subject Key Identifier
        {
            name: "subjectKeyIdentifier",
            keyIdentifier: ski.getBytes(),
        },
        // 7. Authority Key Identifier (self-referencing for self-signed)
        {
            name: "authorityKeyIdentifier",
            keyIdentifier: ski.getBytes(),
        },
    ]);

    // Self-sign with SHA-256
    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    // Compute thumbprint (SHA-1 of DER-encoded certificate, matching .NET's Thumbprint)
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    const thumbprint = forge.md.sha1
        .create()
        .update(certDer.getBytes())
        .digest()
        .toHex()
        .toUpperCase();

    return {
        cert,
        key: keyPair.privateKey,
        thumbprint,
    };
}

/**
 * Check if a forge certificate is a valid ASP.NET Core HTTPS development certificate.
 * This checks the subject, validity period, and presence of the custom OID with an acceptable version.
 */
export function isValidDevCert(
    cert: forge.pki.Certificate,
    minimumVersion: number = MINIMUM_CERTIFICATE_VERSION
): boolean {
    // Check subject
    const cn = cert.subject.getField("CN");
    if (!cn || cn.value !== "localhost") return false;

    // Check not expired
    const now = new Date();
    if (cert.validity.notBefore > now || cert.validity.notAfter < now)
        return false;

    // Check ASP.NET OID version
    const version = getCertificateVersion(cert);
    if (version < 0 || version < minimumVersion) return false;

    return true;
}

/**
 * Extract the version number from the ASP.NET dev cert OID extension.
 * Returns -1 if the certificate does not have the extension.
 */
export function getCertificateVersion(cert: forge.pki.Certificate): number {
    const ext = cert.getExtension({ id: ASPNET_HTTPS_OID });
    if (!ext) return -1;

    const value = (ext as { value?: string }).value;
    if (!value || value.length === 0) return 0;

    // Legacy cert: raw data is the ASCII-encoded friendly name
    if (
        value.length === ASPNET_HTTPS_OID_FRIENDLY_NAME.length &&
        value.charCodeAt(0) === 0x41 // 'A'
    ) {
        return 0;
    }

    // Current format: single byte containing the version number
    return value.charCodeAt(0);
}

/**
 * Compute the thumbprint (SHA-1 hash) of a PEM certificate string.
 */
export function computeThumbprint(pemCert: string): string {
    const cert = forge.pki.certificateFromPem(pemCert);
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    return forge.md.sha1
        .create()
        .update(certDer.getBytes())
        .digest()
        .toHex()
        .toUpperCase();
}

/**
 * Generate a random serial number for the certificate
 * @returns a random certificate serial number
 */
function generateSerialNumber(): string {
    // This shouldn't ever be necessary, but better safe than sorry
    const maxAttempts = 5;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const bytes = Buffer.from(forge.random.getBytesSync(16), "binary");
        // Ensure a non-negative value
        bytes[0] &= 0x7f;

        if (bytes.some((value) => value !== 0)) {
            return bytes.toString("hex");
        }
    }

    throw new Error("Failed to generate a non-zero certificate serial number.");
}
