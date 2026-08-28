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
 * (`{hash}.0` … `{hash}.255`, see `MAX_HASH_SLOTS`) when an occupied slot
 * points at a different, still-present target.
 *
 * Unlike `rehashDirectory`, this only touches the slot for our PEM —
 * other PEMs' hash symlinks are left alone.
 *
 * Throws when no slot is reachable. Returning quietly would let an install
 * report success for a certificate OpenSSL cannot find, which at the point of
 * use is indistinguishable from it not being trusted at all.
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

  // Never silently. A certificate with no reachable slot is one OpenSSL will
  // not find, which at the point of use is indistinguishable from it not being
  // trusted — so reporting a successful install would be a lie. Raising it here
  // also surfaces the unbounded-accumulation problem loudly instead of letting
  // the bound be reached and quietly ignored, which is exactly how the previous
  // ten-slot limit went unnoticed.
  throw new Error(
    `Could not allocate an OpenSSL hash symlink for ${pemFileName} in ${directory}: ` +
      `all ${MAX_HASH_SLOTS} slots for subject hash ${hash} are taken. This certificate would ` +
      `not be found via SSL_CERT_DIR. Remove superseded certificates from that directory.`
  );
}

/**
 * Whether `pemFileName` already has a hash symlink OpenSSL would resolve to it.
 *
 * Exists so callers can treat "installed" as including a reachable link rather
 * than just the files being on disk. An installation made before the subject
 * hash was computed canonically has a symlink under the WRONG hash, so a check
 * that only looks for the PEM and PFX sees a healthy install and skips the
 * repair — leaving trust broken exactly for the users the fix is meant to
 * reach.
 */
export function hasHashSymlink(
  directory: string,
  pemFileName: string,
  pemContent: string
): boolean {
  const hash = computeSubjectHash(pemContent);
  if (!hash) return false;
  for (let i = 0; i < MAX_HASH_SLOTS; i++) {
    const linkPath = path.join(directory, `${hash}.${i}`);

    // A slot is "missing" only when nothing is there. A regular file sitting
    // at `{hash}.N` is OCCUPIED, not a gap: `ensureHashSymlink` steps over it
    // and puts our link in a later slot, and OpenSSL's `by_dir` likewise
    // processes whatever it finds and keeps walking. Reading a non-symlink
    // with readlink raises EINVAL, so treating any error as end-of-search
    // would stop before reaching our link and report "not linked" for a
    // certificate that is in fact reachable.
    let entry: fs.Stats;
    try {
      entry = fs.lstatSync(linkPath);
    } catch {
      return false; // ENOENT — a real gap, and OpenSSL stops here too.
    }
    if (!entry.isSymbolicLink()) continue;

    let target: string;
    try {
      target = fs.readlinkSync(linkPath);
    } catch {
      continue;
    }
    if (target === pemFileName) return true;
  }
  return false;
}

// --- Internal helpers ---

const PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
const PEM_END = "-----END CERTIFICATE-----";

/**
 * Extract the DER bytes of the first certificate in a PEM string.
 *
 * Deliberately `indexOf` + `slice` rather than one regex. The previous form,
 * `/-----BEGIN CERTIFICATE-----\s*([\s\S]*?)\s*-----END CERTIFICATE-----/`,
 * put two `\s*` quantifiers around a lazy `[\s\S]*?` — all three match
 * whitespace, so the engine has an ambiguous split to backtrack over. On input
 * that opens with the BEGIN marker and continues with many spaces but never
 * reaches an END marker, matching degrades to quadratic (CodeQL
 * `js/polynomial-redos`, flagged high).
 *
 * That input is reachable: `rehashDirectory` feeds this every `*.pem` file it
 * finds in the OpenSSL trust directory, and nothing guarantees those files are
 * well-formed. `indexOf` scans linearly and cannot backtrack, and the
 * whitespace strip below uses `/\s/g` — a single character class with no
 * quantifier — so it stays linear too.
 *
 * Behaviour is otherwise unchanged: the first BEGIN paired with the first
 * following END, surrounding whitespace discarded, `null` when either marker
 * is absent.
 */
function pemToDer(pem: string): Buffer | null {
  const begin = pem.indexOf(PEM_BEGIN);
  if (begin < 0) return null;
  const bodyStart = begin + PEM_BEGIN.length;

  const end = pem.indexOf(PEM_END, bodyStart);
  if (end < 0) return null;

  const base64 = pem.slice(bodyStart, end).replace(/\s/g, "");
  if (base64.length === 0) return null;
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
 * OpenSSL's `asn1_string_canon`, verified against `openssl x509 -hash` rather
 * than reconstructed from the source, because the source reads as if it folds
 * bytes in place and it does not.
 *
 * Two things a byte-level reading gets wrong, both confirmed with real certs
 * on OpenSSL 3.0.13:
 *
 * - **Non-UTF-8 string types are transcoded first.** A T61String holding the
 *   UTF-8 bytes of `日本語` hashes to `02c4fa54`; re-tagging those bytes as
 *   UTF8String and hashing gives `e2c402e4`. Only interpreting them as
 *   Latin-1 and re-encoding as UTF-8 reproduces OpenSSL. The same applies to
 *   BMPString (UTF-16BE) and UniversalString (UTF-32BE).
 * - **Folding covers every ASCII whitespace byte, not just `0x20`.** With
 *   `CN` stored as `"a\tb"`, `"a\nb"`, `"a   b"` and `"A   B"`, OpenSSL
 *   returns `49cdc5e0` for all four — so runs of any ASCII whitespace collapse
 *   to one space, and ASCII letters lowercase. Leading whitespace is trimmed
 *   the same way: `"a"`, `" a"` and `"\ta"` all hash to `20b69a40`.
 *
 * Getting either wrong yields a plausible-looking `{hash}.N` link that OpenSSL
 * never opens, which is indistinguishable from an untrusted certificate.
 *
 * Bytes outside ASCII pass through untouched, matching the `!ossl_isascii`
 * branch — safe after transcoding, since every byte of a multi-byte UTF-8
 * sequence has the high bit set and so can't be mistaken for a letter.
 */
function canonicalizeAttributeValue(tag: number, content: Buffer): Buffer {
  if (!CANONICALIZED_STRING_TAGS.has(tag)) return derTlv(tag, content);

  const utf8 = transcodeToUtf8(tag, content);
  if (!utf8) return derTlv(tag, content);

  let start = 0;
  let end = utf8.length;
  while (start < end && isAsciiSpace(utf8[start])) start++;
  while (end > start && isAsciiSpace(utf8[end - 1])) end--;

  const out: number[] = [];
  for (let i = start; i < end; i++) {
    const byte = utf8[i];
    if (isAsciiSpace(byte)) {
      out.push(0x20);
      while (i + 1 < end && isAsciiSpace(utf8[i + 1])) i++;
      continue;
    }
    // ossl_tolower is ASCII-only; bytes with the MSB set pass through.
    out.push(byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
  }

  return derTlv(UTF8_STRING_TAG, Buffer.from(out));
}

/** `ossl_isspace`: space, tab, newline, vertical tab, form feed, carriage return. */
function isAsciiSpace(byte: number): boolean {
  return (
    byte === 0x20 || (byte >= 0x09 && byte <= 0x0d)
  );
}

/**
 * Reinterpret an ASN.1 string's bytes as UTF-8, per its declared type.
 * Returns null for a value whose length can't belong to its type (an odd-length
 * BMPString, say) — the caller then passes the attribute through unchanged
 * rather than inventing an encoding for malformed input.
 */
function transcodeToUtf8(tag: number, content: Buffer): Buffer | null {
  switch (tag) {
    case 0x0c: // UTF8String — already UTF-8.
      return content;
    case 0x13: // PrintableString
    case 0x16: // IA5String
    case 0x1a: // VisibleString
      // Defined as ASCII subsets, so their bytes are already valid UTF-8.
      return content;
    case 0x14: // T61String — OpenSSL decodes these as Latin-1.
      return Buffer.from(content.toString("latin1"), "utf8");
    case 0x1e: {
      // BMPString — UTF-16BE. Node decodes UTF-16LE only, so swap pairs first.
      if (content.length % 2 !== 0) return null;
      const swapped = Buffer.from(content);
      swapped.swap16();
      return Buffer.from(swapped.toString("utf16le"), "utf8");
    }
    case 0x1c: {
      // UniversalString — UTF-32BE, decoded a code point at a time.
      if (content.length % 4 !== 0) return null;
      let text = "";
      for (let i = 0; i < content.length; i += 4) {
        const codePoint = content.readUInt32BE(i);
        if (codePoint > 0x10ffff) return null;
        text += String.fromCodePoint(codePoint);
      }
      return Buffer.from(text, "utf8");
    }
    default:
      return content;
  }
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
