import * as forge from "node-forge";
import * as fs from "fs";

export interface LoadedCert {
  cert: forge.pki.Certificate;
  key: forge.pki.rsa.PrivateKey | null;
  thumbprint: string;
  isExpired: boolean;
}

function computeThumbprintFromCert(cert: forge.pki.Certificate): string {
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
  return forge.md.sha1
    .create()
    .update(certDer.getBytes())
    .digest()
    .toHex()
    .toUpperCase();
}

function buildLoadedCert(
  cert: forge.pki.Certificate,
  key: forge.pki.rsa.PrivateKey | null
): LoadedCert {
  return {
    cert,
    key,
    thumbprint: computeThumbprintFromCert(cert),
    isExpired: cert.validity.notAfter.getTime() < Date.now(),
  };
}

/**
 * Load a PFX/PKCS#12 certificate from disk. Returns the first certificate bag
 * and, when present, its matching private key.
 */
export function loadPfx(filePath: string, password?: string): LoadedCert {
  const bytes = fs.readFileSync(filePath);
  const p12Der = forge.util.createBuffer(bytes.toString("binary"));
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password ?? "");

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[
    forge.pki.oids.certBag
  ];
  if (!certBags || certBags.length === 0 || !certBags[0].cert) {
    throw new Error(`PFX at ${filePath} contains no certificate.`);
  }
  const cert = certBags[0].cert;

  const keyBags =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
      forge.pki.oids.pkcs8ShroudedKeyBag
    ] ?? [];
  const keyBagsUnshrouded =
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] ??
    [];
  const keyBag = keyBags[0] ?? keyBagsUnshrouded[0];
  const key = (keyBag?.key as forge.pki.rsa.PrivateKey | undefined) ?? null;

  return buildLoadedCert(cert, key);
}

/**
 * Load a PEM certificate (and optional matching private key) from disk.
 */
export function loadPemPair(
  certPath: string,
  keyPath?: string | null
): LoadedCert {
  const certPem = fs.readFileSync(certPath, "utf-8");
  const cert = forge.pki.certificateFromPem(certPem);

  let key: forge.pki.rsa.PrivateKey | null = null;
  if (keyPath) {
    const keyPem = fs.readFileSync(keyPath, "utf-8");
    key = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey;
  }

  return buildLoadedCert(cert, key);
}
