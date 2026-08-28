import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import { log } from "../logger";

/**
 * Pure TypeScript implementation of OpenSSL's c_rehash for certificate directories.
 *
 * OpenSSL's `X509_NAME_hash` — the value `by_dir` (i.e. `SSL_CERT_DIR` /
 * `-CApath`) uses to find a certificate by subject — is NOT a hash of the
 * subject's on-the-wire DER. It hashes the *canonical* encoding produced by
 * `X509_NAME_canon`, which differs in two ways that both matter here:
 *
 *   1. Each attribute value is normalized: string types in `ASN1_MASK_CANON`
 *      are re-tagged as UTF8String, ASCII-lowercased, and have leading /
 *      trailing spaces trimmed with internal runs collapsed to one space.
 *   2. The result is the bare concatenation of the DER `SET OF` encodings of
 *      the RDNs — the outer `SEQUENCE` header of the Name is NOT included.
 *
 * SHA-1 over that byte string, first 4 bytes read as a little-endian uint32,
 * formatted as 8-character lowercase hex, is the `{hash}.N` filename OpenSSL
 * looks for. Hashing the raw subject DER instead produces a name nothing ever
 * looks up, which silently disables `SSL_CERT_DIR` trust.
 */

/**
 * ASN.1 string tags OpenSSL's `asn1_string_canon` normalizes (ASN1_MASK_CANON).
 * Anything outside this set — NumericString included — is copied through with
 * its original tag and bytes.
 */
const CANONICALIZED_STRING_TAGS = new Set<number>([
  0x0c, // UTF8String
  0x13, // PrintableString
  0x14, // T61String / TeletexString
  0x16, // IA5String
  0x1a, // VisibleString
  0x1c, // UniversalString
  0x1e, // BMPString
]);

/** Tag OpenSSL re-labels every canonicalized string with. */
const UTF8_STRING_TAG = 0x0c;

/**
 * Upper bound on `{hash}.{n}` slots probed for one subject hash. OpenSSL has
 * no limit of its own; this exists only so a pathological directory can't spin
 * forever. Set far above any plausible dev-cert count so exhausting it means
 * something is genuinely wrong rather than merely busy.
 */
const MAX_HASH_SLOTS = 256;

/**
 * Slot index past which the trust directory is worth remarking on. Ten
 * same-subject certs is already more than a healthy setup accumulates, and
 * silence here is what let the old bound break trust unnoticed.
 */
const CROWDED_HASH_SLOTS = 10;

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

    // Reduce it to OpenSSL's canonical form before hashing.
    const canonical = canonicalizeName(subjectDer);
    if (!canonical) return null;

    const hash = crypto.createHash("sha1").update(canonical).digest();

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
    ensureHashSymlink(directory, certFile, fs.readFileSync(fullPath, "utf-8"));
  }
}

/**
 * Ensure an OpenSSL subject-hash symlink exists for `pemFileName` in
 * `directory`. No-op when a valid slot already points at the same PEM —
 * the caller can re-invoke this safely on every install without producing
 * duplicate `{hash}.0`/`{hash}.1` pairs. Allocates the next free slot
 * (`{hash}.0` … `{hash}.9`) on a real collision with a different target.
 *
 * Unlike `rehashDirectory`, this only touches the slot for our PEM —
 * other PEMs' hash symlinks are left alone.
 */
export function ensureHashSymlink(
  directory: string,
  pemFileName: string,
  pemContent: string
): void {
  const hash = computeSubjectHash(pemContent);
  if (!hash) return;
  // Every ASP.NET dev cert shares the subject `CN=localhost`, so every one of
  // them collides on the SAME hash — slots are consumed by cert COUNT, not by
  // genuine hash collisions. The old bound of 10 therefore ran out in ordinary
  // use: a container that mints a fresh dev cert on each rebuild (the default
  // for most dotnet devcontainer base images, and not something this extension
  // can enforce otherwise) fills ten slots in ten rebuilds, after which this
  // function fell out of the loop and returned silently. The host was then left
  // trusting ten dead certs while the live one had no symlink at all and failed
  // `openssl verify -CApath` — the feature inverted, with no error and no log.
  //
  // OpenSSL imposes no such limit: `by_dir` walks `{hash}.{n}` upward until a
  // file is missing. The corollary is that slots must stay CONTIGUOUS from 0 —
  // a gap makes everything past it unreachable — which is why pruning entries
  // has to re-densify via `rehashDirectory` rather than unlink in place.
  //
  // Catch EEXIST so a concurrent rehash from another process doesn't crash the
  // caller.
  for (let i = 0; i < MAX_HASH_SLOTS; i++) {
    const linkName = `${hash}.${i}`;
    const linkPath = path.join(directory, linkName);

    // Use lstat (instead of existsSync) so dangling symlinks are detected
    // as "occupied" and can be reclaimed.
    let existing: fs.Stats | undefined;
    try {
      existing = fs.lstatSync(linkPath);
    } catch {
      // ENOENT — slot is free.
    }

    if (existing) {
      if (!existing.isSymbolicLink()) continue; // not ours; skip
      let target: string;
      try {
        target = fs.readlinkSync(linkPath);
      } catch {
        continue;
      }
      if (target === pemFileName) return; // already correct
      const targetPath = path.isAbsolute(target)
        ? target
        : path.join(directory, target);
      if (fs.existsSync(targetPath)) continue; // live collision; next slot
      // Dangling — reclaim the slot. Hash symlinks are written exclusively
      // by this extension, so a dangling one is leftover state we own.
      try {
        fs.unlinkSync(linkPath);
      } catch {
        continue;
      }
    }

    try {
      fs.symlinkSync(pemFileName, linkPath);
      if (i >= CROWDED_HASH_SLOTS) {
        log(
          `OpenSSL trust dir ${directory} now holds ${i + 1} certificates sharing subject hash ${hash}. ` +
            `Trust is still correct, but nothing prunes superseded certificates — see the accumulation ` +
            `note in AGENTS.md.`
        );
      }
      return;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") continue;
      throw err;
    }
  }

  // Never silently: a cert with no reachable slot is a cert OpenSSL will not
  // find, which is indistinguishable from "not trusted" at the point of use.
  log(
    `[warn] Could not allocate an OpenSSL hash symlink for ${pemFileName} in ${directory}: ` +
      `all ${MAX_HASH_SLOTS} slots for subject hash ${hash} are taken. This certificate will NOT be ` +
      `found via SSL_CERT_DIR. Remove superseded certificates from that directory and re-run the sync.`
  );
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
  const offset = 0;

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

/**
 * Reduce a DER-encoded X.509 `Name` to the byte string OpenSSL hashes in
 * `X509_NAME_hash`: each RDN re-encoded as a DER `SET OF` over canonicalized
 * attributes, concatenated, with NO outer `SEQUENCE` header.
 */
function canonicalizeName(nameDer: Buffer): Buffer | null {
  const name = readTag(nameDer, 0);
  if (!name || name.tag !== 0x30) return null;

  const nameEnd = name.contentOffset + name.contentLength;
  if (nameEnd > nameDer.length) return null;

  const rdnEncodings: Buffer[] = [];
  let pos = name.contentOffset;
  while (pos < nameEnd) {
    const rdn = readTag(nameDer, pos);
    if (!rdn || rdn.tag !== 0x31) return null;
    const rdnEnd = rdn.contentOffset + rdn.contentLength;
    if (rdnEnd > nameEnd) return null;

    const attributes: Buffer[] = [];
    let attrPos = rdn.contentOffset;
    while (attrPos < rdnEnd) {
      const attr = readTag(nameDer, attrPos);
      if (!attr || attr.tag !== 0x30) return null;
      const attrEnd = attr.contentOffset + attr.contentLength;
      if (attrEnd > rdnEnd) return null;

      const type = readTag(nameDer, attr.contentOffset);
      if (!type || type.tag !== 0x06) return null;
      const typeEnd = type.contentOffset + type.contentLength;
      if (typeEnd > attrEnd) return null;

      const value = readTag(nameDer, typeEnd);
      if (!value) return null;
      if (value.contentOffset + value.contentLength > attrEnd) return null;

      const canonValue = canonicalizeAttributeValue(
        value.tag,
        nameDer.subarray(
          value.contentOffset,
          value.contentOffset + value.contentLength
        )
      );
      attributes.push(
        derTlv(
          0x30,
          Buffer.concat([nameDer.subarray(attr.contentOffset, typeEnd), canonValue])
        )
      );

      attrPos = attrEnd;
    }

    // DER requires SET OF members to be sorted by their encodings.
    attributes.sort(compareDerSetMembers);
    rdnEncodings.push(derTlv(0x31, Buffer.concat(attributes)));

    pos = rdnEnd;
  }

  return Buffer.concat(rdnEncodings);
}

/**
 * OpenSSL's `asn1_string_canon`: string types in ASN1_MASK_CANON are re-tagged
 * as UTF8String and normalized (ASCII-lowercased, leading/trailing spaces
 * dropped, internal space runs collapsed to one). Everything else is copied
 * through untouched. Note that OpenSSL does not transcode BMPString /
 * UniversalString bytes to UTF-8 here — it only relabels the tag — so we
 * mirror that byte-for-byte rather than "fixing" it.
 */
function canonicalizeAttributeValue(tag: number, content: Buffer): Buffer {
  if (!CANONICALIZED_STRING_TAGS.has(tag)) return derTlv(tag, content);

  let start = 0;
  let end = content.length;
  while (start < end && content[start] === 0x20) start++;
  while (end > start && content[end - 1] === 0x20) end--;

  const out: number[] = [];
  for (let i = start; i < end; i++) {
    const byte = content[i];
    if (byte === 0x20) {
      out.push(0x20);
      while (i + 1 < end && content[i + 1] === 0x20) i++;
      continue;
    }
    // ossl_tolower is ASCII-only; bytes with the MSB set pass through.
    out.push(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
  }

  return derTlv(UTF8_STRING_TAG, Buffer.from(out));
}

/**
 * DER `SET OF` ordering, matching OpenSSL's `der_cmp`: compare the shared
 * prefix, then let the shorter encoding sort first.
 */
function compareDerSetMembers(a: Buffer, b: Buffer): number {
  const shared = Math.min(a.length, b.length);
  const diff = Buffer.compare(a.subarray(0, shared), b.subarray(0, shared));
  return diff !== 0 ? diff : a.length - b.length;
}

/** Encode a single DER TLV with a minimal definite-form length. */
function derTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
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
