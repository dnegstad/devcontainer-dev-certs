/**
 * Legacy PKCS#12 PBE decryptor — narrowly scoped to one algorithm.
 *
 * # Why this exists
 *
 * `parsePfx` strictly accepts only modern PBES2/AES encryption for cert
 * and key bags. We added that policy because every cert WE produce uses
 * PBES2 and every legacy PBE algorithm in the PKCS#12 family is
 * cryptographically weak. The lone exception is the cert that
 * `aspnetcore`'s `MacOSCertificateManager.SaveCertificateCore` writes
 * into `~/.aspnet/dev-certs/https/aspnetcore-localhost-*.pfx`: it calls
 * `certificate.Export(X509ContentType.Pfx)` with no password, and
 * dotnet/runtime's managed Pkcs12 writer's no-password default on Unix
 * is `pbeWithSHA1And3-KeyTripleDES-CBC` (OID 1.2.840.113549.1.12.1.3).
 * Confirmed empirically on .NET 10.0.301 / runtime 10.0.9, both in CI
 * (macos-latest) and on a maintainer's local Mac.
 *
 * Without this module, `DotnetBackend.generate` on macOS — the platform
 * `hostCertGenerator=auto` PREFERS — fails because `findExistingDevCert`
 * can't read aspnetcore's disk cache. Same blocker hits any user-supplied
 * dotnet-on-macOS-produced PFX that flows through `parsePfx`. Scoping is
 * per-OID: only the algorithm we observed in practice is accepted; the
 * other five RC2/RC4/2-key-3DES OIDs in the PKCS#12 family remain
 * rejected with the original error.
 *
 * # Removal criteria
 *
 * Delete this module (and its companion test file) when ALL of the
 * following hold:
 *
 *   1. Our floor-supported .NET SDK no longer produces 3DES-encrypted
 *      disk-cache PFXes on macOS — i.e. aspnetcore has switched
 *      `MacOSCertificateManager.SaveCertificateCore` from
 *      `Export(X509ContentType.Pfx)` to `ExportPkcs12(PbeParameters(...))`
 *      with explicit PBES2 parameters, matching the
 *      `OpenSslDirectoryBasedStoreProvider` Linux path. Verify via
 *      `tests/dotnetMacosCache.integration.test.ts` against the new
 *      minimum SDK version.
 *   2. No user-facing report has surfaced legacy-PBE PFXes from any
 *      other source that we care about loading.
 *
 * Removal steps:
 *
 *   1. Delete this file.
 *   2. Delete `tests/pkcs12LegacyPbe.test.ts` (in the UI extension test
 *      tree).
 *   3. Delete `test/fixtures/pkcs12-legacy-3des.pfx`.
 *   4. In `src/shared/src/cert/pfx.ts`:
 *      - Add `"1.2.840.113549.1.12.1.3": "pbeWithSHAAnd3-KeyTripleDES-CBC"`
 *        back to `REJECTED_LEGACY_PBE_NAMES`.
 *      - Revert `decryptSafeContents` and `decryptShroudedKeyBag` to
 *        their original "reject anything not PBES2" form (drop the
 *        `isSupportedLegacyPbe` branches and the imports from this
 *        module).
 *
 * # References
 *
 *   - RFC 7292 §4.2: PKCS#12 PBE-with-SHA OIDs.
 *   - RFC 7292 Appendix B: PKCS#12 v1.0 key derivation function.
 *   - RFC 7292 Appendix C: `pkcs-12PbeParams` ASN.1 definition.
 *   - aspnetcore source: src/Shared/CertificateGeneration/
 *     MacOSCertificateManager.cs `SaveCertificateCore`
 *     (`certificate.Export(X509ContentType.Pfx)` with no password).
 *   - dotnet/runtime behavior: managed Pkcs12 writer's no-password
 *     default on Unix is 3DES-with-SHA1, 2000 iterations.
 */

import { createDecipheriv, createHash } from "crypto";
import type * as asn1js from "asn1js";

/**
 * The one legacy PBE OID this module decodes. Every other legacy
 * PKCS#12 PBE OID stays in `REJECTED_LEGACY_PBE_NAMES` in pfx.ts.
 */
export const SUPPORTED_LEGACY_PBE_OID = "1.2.840.113549.1.12.1.3";

/** Type-guard: is `oid` the one legacy OID we support? */
export function isSupportedLegacyPbe(oid: string): boolean {
  return oid === SUPPORTED_LEGACY_PBE_OID;
}

export interface LegacyPbeParams {
  /** Salt bytes from the pkcs-12PbeParams ASN.1 sequence. */
  salt: Buffer;
  /** Iteration count from the pkcs-12PbeParams ASN.1 sequence. */
  iterations: number;
}

/**
 * Parse the AlgorithmIdentifier.parameters field as `pkcs-12PbeParams`
 * (RFC 7292 Appendix C):
 *
 *     pkcs-12PbeParams ::= SEQUENCE {
 *         salt        OCTET STRING,
 *         iterations  INTEGER
 *     }
 *
 * The same format is shared by all six legacy OIDs in the
 * `1.2.840.113549.1.12.1.*` family.
 */
export function parseLegacyPbeParams(
  algorithmParameters: unknown
): LegacyPbeParams {
  const seq = algorithmParameters as asn1js.Sequence | undefined;
  const items = seq?.valueBlock?.value;
  if (!items || items.length < 2) {
    throw new Error(
      "Malformed pkcs-12PbeParams: expected SEQUENCE { salt, iterations }."
    );
  }
  const saltAsn1 = items[0] as asn1js.OctetString;
  const iterAsn1 = items[1] as asn1js.Integer;
  return {
    salt: Buffer.from(saltAsn1.valueBlock.valueHex),
    iterations: iterAsn1.valueBlock.valueDec,
  };
}

/**
 * Decrypt a body protected by `pbeWithSHA1And3-KeyTripleDES-CBC`.
 *
 *   1. Derive the 24-byte 3DES key via PKCS#12 v1.0 KDF (diversifier 1).
 *   2. Derive the 8-byte IV via PKCS#12 v1.0 KDF (diversifier 2).
 *   3. Decrypt with `des-ede3-cbc` (Node's built-in crypto).
 *
 * For an EMPTY password we try two derivation conventions and return
 * whichever decrypts cleanly:
 *
 *   - "with null terminator" — encode `""` as the 2-byte UTF-16BE null
 *     terminator and derive from that. OpenSSL, Bouncy Castle, and our
 *     openssl-generated test fixture all use this convention.
 *   - "literal empty bytes" — RFC 7292's literal wording ("if password
 *     is the empty string, then so is P"). dotnet/runtime's managed
 *     PKCS#12 writer takes this branch; its on-disk macOS dev-cert
 *     cache decrypts ONLY under this convention. Confirmed empirically
 *     on .NET 10.0.301 — CI hit "bad decrypt" with the OpenSSL
 *     convention applied uniformly.
 *
 * For non-empty passwords there's no ambiguity: implementations agree
 * the password is UTF-16BE bytes plus a trailing null terminator, and
 * only that path is tried.
 *
 * PKCS#7 padding the cipher leaves on the plaintext is stripped by
 * Node's `decipher.final()`. A `final()` throw under both conventions
 * propagates outward — the password supplied is wrong, the file is
 * corrupt, or aspnetcore changed its export convention again.
 */
export function decryptLegacyPbe(
  oid: string,
  params: LegacyPbeParams,
  ciphertext: Buffer,
  password: string
): Buffer {
  if (oid !== SUPPORTED_LEGACY_PBE_OID) {
    throw new Error(
      `decryptLegacyPbe called with unsupported OID ${oid}. ` +
        `Call sites should check isSupportedLegacyPbe(oid) first.`
    );
  }
  // Non-empty password: single canonical encoding.
  if (password.length > 0) {
    return tryDecrypt3DesPbe(params, ciphertext, password, true);
  }
  // Empty password: try OpenSSL convention first (matches our test
  // fixture + most real-world legacy PFXes), fall back to RFC-literal
  // (matches dotnet's macOS disk cache).
  try {
    return tryDecrypt3DesPbe(params, ciphertext, "", true);
  } catch {
    return tryDecrypt3DesPbe(params, ciphertext, "", false);
  }
}

function tryDecrypt3DesPbe(
  params: LegacyPbeParams,
  ciphertext: Buffer,
  password: string,
  includeNullTerminator: boolean
): Buffer {
  const key = pkcs12Kdf(
    password,
    params.salt,
    params.iterations,
    1,
    24,
    includeNullTerminator
  );
  const iv = pkcs12Kdf(
    password,
    params.salt,
    params.iterations,
    2,
    8,
    includeNullTerminator
  );
  const decipher = createDecipheriv("des-ede3-cbc", key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * PKCS#12 v1.0 key derivation function (RFC 7292 Appendix B). NOT
 * PBKDF2 — this is the legacy SHA-1-based diversifier KDF specifically
 * defined for PKCS#12. Used here for both encryption key (diversifier
 * 1) and IV (diversifier 2) derivation against the same salt and
 * iteration count.
 *
 * `includeNullTerminator` controls the well-known empty-password
 * disagreement (see `decryptLegacyPbe`). For non-empty passwords every
 * relevant implementation appends the UTF-16BE null terminator, so the
 * flag is IGNORED for them — the function always uses the
 * null-terminated encoding to match real-world interop.
 *
 * Exported for testing only — call sites should use `decryptLegacyPbe`,
 * which handles the empty-password convention fallback.
 */
export function pkcs12Kdf(
  password: string,
  salt: Buffer,
  iterations: number,
  diversifier: 1 | 2 | 3,
  outputLength: number,
  includeNullTerminator = true
): Buffer {
  const u = 20; // SHA-1 output size (bytes)
  const v = 64; // SHA-1 input block size (bytes)

  // D: v bytes, each equal to the diversifier byte.
  const D = Buffer.alloc(v, diversifier);

  // S: salt repeated to a multiple of v bytes (empty if salt is empty).
  const S = repeatToMultiple(salt, v);

  // P: password as UTF-16BE bytes, repeated to a multiple of v bytes.
  // Non-empty passwords always include the trailing null terminator
  // (every implementation we care about agrees there); for the empty
  // password, the `includeNullTerminator` flag picks between the two
  // contested conventions that callers iterate over.
  let pwBytes: Buffer;
  if (password.length === 0) {
    pwBytes = includeNullTerminator
      ? Buffer.from([0x00, 0x00])
      : Buffer.alloc(0);
  } else {
    pwBytes = utf16BeWithNul(password);
  }
  const P = repeatToMultiple(pwBytes, v);

  // I = S || P.
  let I = Buffer.concat([S, P]);

  // Number of u-byte rounds needed to fill the output.
  const rounds = Math.ceil(outputLength / u);
  const out = Buffer.alloc(outputLength);

  for (let i = 1; i <= rounds; i++) {
    // A_i = H^c(D || I), with H = SHA-1 and c = iterations.
    let A = createHash("sha1").update(D).update(I).digest();
    for (let k = 1; k < iterations; k++) {
      A = createHash("sha1").update(A).digest();
    }

    // Copy A_i into the output (truncated on the last round if needed).
    const offset = (i - 1) * u;
    const take = Math.min(u, outputLength - offset);
    A.copy(out, offset, 0, take);

    if (i < rounds) {
      // B = A repeated to v bytes.
      const B = Buffer.alloc(v);
      for (let k = 0; k < v; k++) B[k] = A[k % u];

      // For each v-byte block I_l of I, set I_l = (I_l + B + 1) mod 2^(8v).
      // Big-endian arithmetic with carry propagation.
      const blockCount = I.length / v;
      const newI = Buffer.alloc(I.length);
      for (let l = 0; l < blockCount; l++) {
        let carry = 1; // the +1 in (I_l + B + 1)
        for (let m = v - 1; m >= 0; m--) {
          const sum = I[l * v + m] + B[m] + carry;
          newI[l * v + m] = sum & 0xff;
          carry = sum >>> 8;
        }
        // Overflow above 2^(8v) is dropped per the mod 2^(8v) in the spec.
      }
      I = newI;
    }
  }

  return out;
}

/**
 * Encode a string as UTF-16BE plus a trailing 16-bit null character —
 * the password representation PKCS#12 v1.0 KDF expects for non-empty
 * strings under every convention we care about. Surrogate pairs are
 * preserved (the `String.prototype.charCodeAt` iteration produces the
 * UTF-16 code units directly).
 */
function utf16BeWithNul(s: string): Buffer {
  const buf = Buffer.alloc((s.length + 1) * 2);
  for (let i = 0; i < s.length; i++) {
    buf.writeUInt16BE(s.charCodeAt(i), i * 2);
  }
  // Trailing 2 bytes are already zero (Buffer.alloc zero-fills).
  return buf;
}

/**
 * Repeat `src` (cycling) into a buffer whose length is the smallest
 * multiple of `block` >= src.length. An empty `src` yields an empty
 * result (matches the RFC 7292 note for empty salt / password).
 */
function repeatToMultiple(src: Buffer, block: number): Buffer {
  if (src.length === 0) return Buffer.alloc(0);
  const len = block * Math.ceil(src.length / block);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = src[i % src.length];
  return out;
}
