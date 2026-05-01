import * as fs from "fs";
import { DevCert, DevKey } from "./types";
import { parsePfx } from "./pfx";

export interface LoadedCert {
  cert: DevCert;
  key: DevKey | null;
  thumbprint: string;
  isExpired: boolean;
}

function buildLoadedCert(cert: DevCert, key: DevKey | null): LoadedCert {
  return {
    cert,
    key,
    thumbprint: cert.thumbprint,
    isExpired: cert.notAfter.getTime() < Date.now(),
  };
}

/**
 * Load a PFX/PKCS#12 certificate from disk. Returns the first certificate bag
 * and, when present, its matching private key.
 */
export async function loadPfx(
  filePath: string,
  password?: string
): Promise<LoadedCert> {
  const bytes = fs.readFileSync(filePath);
  const { cert, key } = await parsePfx(bytes, password);
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
  const cert = new DevCert(certPem);

  let key: DevKey | null = null;
  if (keyPath) {
    const keyPem = fs.readFileSync(keyPath, "utf-8");
    key = DevKey.fromPem(keyPem);
  }

  return buildLoadedCert(cert, key);
}
