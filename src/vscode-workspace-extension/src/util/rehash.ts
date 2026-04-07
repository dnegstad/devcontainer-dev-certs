import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

/**
 * Pure TypeScript implementation of OpenSSL's c_rehash for certificate directories.
 *
 * OpenSSL uses the "subject name hash" to look up certificates by filename.
 * The hash is computed as: SHA-1 of the DER-encoded canonical subject name,
 * then the first 4 bytes interpreted as a little-endian 32-bit unsigned integer,
 * formatted as 8-character lowercase hex.
 *
 * This matches the simplified c_rehash in .NET's UnixCertificateManager.
 */

/**
 * Compute the OpenSSL subject hash from a PEM certificate string.
 * Returns the 8-character hex hash string, or null if the cert cannot be parsed.
 */
export function computeSubjectHash(pemCert: string): string | null {
  try {
    // Parse the PEM to get DER bytes
    const derBytes = pemToDer(pemCert);
    if (!derBytes) return null;

    // Extract the subject field from the TBSCertificate
    const subjectDer = extractSubjectDer(derBytes);
    if (!subjectDer) return null;

    // Compute SHA-1 hash of the DER-encoded subject
    const hash = crypto.createHash("sha1").update(subjectDer).digest();

    // Take first 4 bytes as little-endian uint32, format as 8-char hex
    const value = hash.readUInt32LE(0);
    return value.toString(16).padStart(8, "0");
  } catch {
    return null;
  }
}

/**
 * Create hash symlinks in a directory for all PEM/CRT files.
 * Removes existing hash symlinks first, then creates new ones.
 */
export function rehashDirectory(directory: string): void {
  const entries = fs.readdirSync(directory);

  // Remove existing hash symlinks
  for (const entry of entries) {
    const fullPath = path.join(directory, entry);
    if (isHashSymlink(entry) && isSymlink(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }

  // Create new hash symlinks
  const certFiles = entries.filter((f) => /\.(pem|crt|cer)$/i.test(f));
  for (const certFile of certFiles) {
    const fullPath = path.join(directory, certFile);
    if (isSymlink(fullPath)) continue; // Skip symlinks themselves

    const pemContent = fs.readFileSync(fullPath, "utf-8");
    const hash = computeSubjectHash(pemContent);
    if (!hash) continue;

    // Find available slot
    for (let i = 0; i < 10; i++) {
      const linkName = `${hash}.${i}`;
      const linkPath = path.join(directory, linkName);
      if (!fs.existsSync(linkPath)) {
        fs.symlinkSync(certFile, linkPath);
        break;
      }
    }
  }
}

/**
 * Create a single hash symlink for a specific PEM file.
 */
export function createHashSymlink(
  directory: string,
  pemFileName: string,
  pemContent: string
): void {
  const hash = computeSubjectHash(pemContent);
  if (!hash) return;

  for (let i = 0; i < 10; i++) {
    const linkName = `${hash}.${i}`;
    const linkPath = path.join(directory, linkName);
    if (!fs.existsSync(linkPath)) {
      fs.symlinkSync(pemFileName, linkPath);
      break;
    }
  }
}

// --- Internal helpers ---

function pemToDer(pem: string): Buffer | null {
  const match = pem.match(
    /-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/
  );
  if (!match) return null;
  const base64 = match[1].replace(/\s/g, "");
  return Buffer.from(base64, "base64");
}

/**
 * Extract the Subject field (as raw DER bytes) from an X.509 certificate.
 *
 * X.509 structure (simplified):
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate    TBSCertificate,
 *     ...
 *   }
 *   TBSCertificate ::= SEQUENCE {
 *     version         [0] EXPLICIT INTEGER OPTIONAL,
 *     serialNumber    INTEGER,
 *     signature       AlgorithmIdentifier,
 *     issuer          Name,
 *     validity        Validity,
 *     subject         Name,     <-- this is what we want
 *     ...
 *   }
 */
function extractSubjectDer(certDer: Buffer): Buffer | null {
  let offset = 0;

  // Certificate SEQUENCE
  const cert = readTag(certDer, offset);
  if (!cert || cert.tag !== 0x30) return null;

  // TBSCertificate SEQUENCE
  const tbs = readTag(certDer, cert.contentOffset);
  if (!tbs || tbs.tag !== 0x30) return null;

  let pos = tbs.contentOffset;

  // version [0] EXPLICIT - optional, skip if present
  const maybeVersion = readTag(certDer, pos);
  if (!maybeVersion) return null;
  if (maybeVersion.tag === 0xa0) {
    // version is present, skip it
    pos = maybeVersion.contentOffset + maybeVersion.contentLength;
  }

  // serialNumber INTEGER - skip
  const serial = readTag(certDer, pos);
  if (!serial) return null;
  pos = serial.contentOffset + serial.contentLength;

  // signature AlgorithmIdentifier SEQUENCE - skip
  const sigAlg = readTag(certDer, pos);
  if (!sigAlg) return null;
  pos = sigAlg.contentOffset + sigAlg.contentLength;

  // issuer Name SEQUENCE - skip
  const issuer = readTag(certDer, pos);
  if (!issuer) return null;
  pos = issuer.contentOffset + issuer.contentLength;

  // validity Validity SEQUENCE - skip
  const validity = readTag(certDer, pos);
  if (!validity) return null;
  pos = validity.contentOffset + validity.contentLength;

  // subject Name SEQUENCE - THIS IS WHAT WE WANT
  const subject = readTag(certDer, pos);
  if (!subject) return null;

  // Return the full TLV (tag + length + content) of the subject
  return certDer.subarray(pos, subject.contentOffset + subject.contentLength);
}

interface TlvResult {
  tag: number;
  contentOffset: number;
  contentLength: number;
}

/**
 * Read an ASN.1 TLV (Tag-Length-Value) at the given offset.
 */
function readTag(buf: Buffer, offset: number): TlvResult | null {
  if (offset >= buf.length) return null;

  const tag = buf[offset];
  let pos = offset + 1;

  if (pos >= buf.length) return null;

  let length = buf[pos];
  pos++;

  if (length & 0x80) {
    // Long form length
    const numBytes = length & 0x7f;
    if (numBytes > 4 || pos + numBytes > buf.length) return null;
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[pos];
      pos++;
    }
  }

  return {
    tag,
    contentOffset: pos,
    contentLength: length,
  };
}

function isHashSymlink(filename: string): boolean {
  // Hash symlinks match pattern: 8 hex chars + dot + digit(s)
  return /^[0-9a-f]{8}\.\d+$/.test(filename);
}

function isSymlink(filePath: string): boolean {
  try {
    return fs.lstatSync(filePath).isSymbolicLink();
  } catch {
    return false;
  }
}
