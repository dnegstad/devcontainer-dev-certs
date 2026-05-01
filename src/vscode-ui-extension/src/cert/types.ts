/**
 * Backend-agnostic certificate / private-key wrappers used throughout the
 * UI extension. The certificate side wraps `@peculiar/x509`'s `X509Certificate`;
 * private keys wrap Node's `KeyObject`.
 *
 * This decouples the rest of the codebase from any one X.509 / asymmetric-key
 * library and lets the same types support RSA, ECDSA, and Ed25519 / Ed448.
 */

import {
  createHash,
  createPrivateKey,
  type KeyObject,
  webcrypto,
} from "node:crypto";
import { X509Certificate as PeculiarX509 } from "@peculiar/x509";

export type DevKeyAlgorithm = "rsa" | "ec" | "ed25519" | "ed448";

/**
 * Wrapper around an X.509 certificate parsed by `@peculiar/x509`.
 *
 * Provides convenience accessors for the bits the rest of the extension cares
 * about (subject CN, validity dates, extensions, thumbprint) without exposing
 * the underlying parser API.
 */
export class DevCert {
  readonly inner: PeculiarX509;
  private _der?: Buffer;
  private _pem?: string;

  constructor(input: PeculiarX509 | Buffer | Uint8Array | ArrayBuffer | string) {
    if (input instanceof PeculiarX509) {
      this.inner = input;
    } else if (Buffer.isBuffer(input)) {
      // Node `Buffer<ArrayBufferLike>` isn't structurally assignable to the
      // strict ArrayBuffer-backed view that @peculiar/x509 expects under
      // newer TS lib types; copy into a fresh ArrayBuffer to satisfy it.
      this.inner = new PeculiarX509(toArrayBuffer(input));
    } else if (input instanceof Uint8Array) {
      this.inner = new PeculiarX509(toArrayBuffer(input));
    } else if (input instanceof ArrayBuffer) {
      this.inner = new PeculiarX509(input);
    } else {
      this.inner = new PeculiarX509(input);
    }
  }

  /** DER-encoded certificate bytes. */
  get der(): Buffer {
    this._der ??= Buffer.from(this.inner.rawData);
    return this._der;
  }

  /** PEM-encoded certificate (BEGIN/END CERTIFICATE). */
  get pem(): string {
    this._pem ??= this.inner.toString("pem");
    return this._pem;
  }

  /** First Common Name in the subject Distinguished Name, or null. */
  get subjectCN(): string | null {
    const cn = this.inner.subjectName.getField("CN");
    return cn.length > 0 ? cn[0] : null;
  }

  /** First Common Name in the issuer Distinguished Name, or null. */
  get issuerCN(): string | null {
    const cn = this.inner.issuerName.getField("CN");
    return cn.length > 0 ? cn[0] : null;
  }

  /** Lowercase hex serial number. */
  get serialNumber(): string {
    return this.inner.serialNumber.toLowerCase();
  }

  get notBefore(): Date {
    return this.inner.notBefore;
  }

  get notAfter(): Date {
    return this.inner.notAfter;
  }

  /** SHA-1 thumbprint, uppercase hex (matches .NET's `Thumbprint`). */
  get thumbprint(): string {
    return createHash("sha1").update(this.der).digest("hex").toUpperCase();
  }

  /**
   * Look up an extension by OID.
   * Returns the extension's critical flag and the raw DER `extnValue`,
   * or null if the extension is absent.
   */
  getExtension(oid: string): { critical: boolean; value: Buffer } | null {
    const ext = this.inner.getExtension(oid);
    if (!ext) return null;
    return { critical: ext.critical, value: Buffer.from(ext.value) };
  }

  hasExtension(oid: string): boolean {
    return this.inner.getExtension(oid) !== null;
  }
}

/**
 * Wrapper around an asymmetric private key (Node `KeyObject`).
 * Exposes PKCS#8 PEM/DER encoding plus algorithm metadata, and can convert
 * to a webcrypto `CryptoKey` when needed by `@peculiar/x509` or `pkijs`.
 */
export class DevKey {
  readonly keyObject: KeyObject;
  readonly algorithm: DevKeyAlgorithm;

  private _pem?: string;
  private _der?: Buffer;

  constructor(keyObject: KeyObject) {
    if (keyObject.type !== "private") {
      throw new Error(
        `DevKey requires a private key (got '${keyObject.type}').`
      );
    }
    this.keyObject = keyObject;
    this.algorithm = mapAlgorithm(keyObject.asymmetricKeyType);
  }

  /** Build from a PEM string (PKCS#1 RSA, PKCS#8, or SEC1 EC). */
  static fromPem(pem: string): DevKey {
    return new DevKey(createPrivateKey({ key: pem, format: "pem" }));
  }

  /** Build from PKCS#8 DER bytes. */
  static fromPkcs8Der(der: Buffer | Uint8Array): DevKey {
    const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
    return new DevKey(
      createPrivateKey({ key: buf, format: "der", type: "pkcs8" })
    );
  }

  /** Build from a webcrypto `CryptoKey` (must be extractable). */
  static async fromCryptoKey(key: CryptoKey): Promise<DevKey> {
    const der = await webcrypto.subtle.exportKey("pkcs8", key);
    return DevKey.fromPkcs8Der(Buffer.from(der));
  }

  /** PKCS#8 PEM (unencrypted). */
  get pem(): string {
    this._pem ??= this.keyObject.export({
      type: "pkcs8",
      format: "pem",
    }) as string;
    return this._pem;
  }

  /** PKCS#8 DER (unencrypted). */
  get der(): Buffer {
    this._der ??= this.keyObject.export({ type: "pkcs8", format: "der" });
    return this._der;
  }

  /** Convert to a webcrypto `CryptoKey` for use with @peculiar/x509 / pkijs. */
  async toCryptoKey(): Promise<CryptoKey> {
    return importPrivateKey(this);
  }
}

function mapAlgorithm(asym: string | undefined): DevKeyAlgorithm {
  switch (asym) {
    case "rsa":
    case "rsa-pss":
      return "rsa";
    case "ec":
      return "ec";
    case "ed25519":
      return "ed25519";
    case "ed448":
      return "ed448";
    default:
      throw new Error(`Unsupported private key type: ${asym ?? "unknown"}`);
  }
}

async function importPrivateKey(key: DevKey): Promise<CryptoKey> {
  const { algorithm, der } = key;
  const subtle = webcrypto.subtle;

  if (algorithm === "rsa") {
    return subtle.importKey(
      "pkcs8",
      bufferToArrayBuffer(der),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["sign"]
    );
  }

  if (algorithm === "ec") {
    const namedCurve = inferEcCurve(key.keyObject);
    return subtle.importKey(
      "pkcs8",
      bufferToArrayBuffer(der),
      { name: "ECDSA", namedCurve },
      true,
      ["sign"]
    );
  }

  if (algorithm === "ed25519") {
    return subtle.importKey(
      "pkcs8",
      bufferToArrayBuffer(der),
      { name: "Ed25519" },
      true,
      ["sign"]
    );
  }

  if (algorithm === "ed448") {
    return subtle.importKey(
      "pkcs8",
      bufferToArrayBuffer(der),
      { name: "Ed448" },
      true,
      ["sign"]
    );
  }

  throw new Error(
    `Unsupported algorithm for CryptoKey import: ${String(algorithm)}`
  );
}

function inferEcCurve(keyObject: KeyObject): string {
  const detail = (keyObject as unknown as { asymmetricKeyDetails?: { namedCurve?: string } })
    .asymmetricKeyDetails;
  const named = detail?.namedCurve;
  if (!named) {
    throw new Error("Could not determine EC named curve for private key.");
  }
  switch (named) {
    case "prime256v1":
    case "secp256r1":
    case "P-256":
      return "P-256";
    case "secp384r1":
    case "P-384":
      return "P-384";
    case "secp521r1":
    case "P-521":
      return "P-521";
    default:
      throw new Error(`Unsupported EC curve: ${named}`);
  }
}

function bufferToArrayBuffer(buf: Buffer): ArrayBuffer {
  return toArrayBuffer(buf);
}

function toArrayBuffer(view: Buffer | Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(view.byteLength);
  new Uint8Array(ab).set(view);
  return ab;
}
