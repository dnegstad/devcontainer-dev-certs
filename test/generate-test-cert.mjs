#!/usr/bin/env node
// Generates a self-signed RSA-2048 server certificate for end-to-end testing
// the `devcontainerDevCerts.defaultKestrelCertificate` flow.
//
// Usage (from repo root):
//   npm run gen:test-cert
//
// Output:
//   .out/test-fixtures/corp-wildcard.pem   PEM-encoded certificate
//   .out/test-fixtures/corp-wildcard.key   PEM-encoded PKCS#8 private key
//
// The cert is deliberately NOT a dotnet-dev-cert: CN is corp-wildcard.corp.test
// (not localhost), and the ASP.NET HTTPS dev-cert OID extension is absent, so
// it can't be mistaken for the auto-generated dev cert by any code path that
// inspects either marker. SANs include `localhost` + loopback IPs so Kestrel
// terminating https://localhost:7001 with this cert still passes hostname
// verification by curl / the browser.

// @peculiar/x509 uses tsyringe DI, which needs the reflect-metadata polyfill
// installed before any of its decorators evaluate.
import "reflect-metadata";

import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";
import { createHash, randomBytes, webcrypto } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

cryptoProvider.set(webcrypto);

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const outDir = resolve(repoRoot, ".out", "test-fixtures");
const pemPath = resolve(outDir, "corp-wildcard.pem");
const keyPath = resolve(outDir, "corp-wildcard.key");

mkdirSync(outDir, { recursive: true });

// Backdate `notBefore` slightly so freshly minted certs aren't rejected by
// strict clients sampling time before the file lands on disk.
const notBefore = new Date(Date.now() - 5 * 60 * 1000);
const notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000);

const keyPair = await webcrypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["sign", "verify"],
);

const subject = "CN=corp-wildcard.corp.test, O=Devcontainer Dev Certs E2E";
const serial = randomBytes(16);
serial[0] &= 0x7f; // force non-negative

const cert = await X509CertificateGenerator.create({
  serialNumber: Buffer.from(serial).toString("hex"),
  subject,
  issuer: subject,
  notBefore,
  notAfter,
  signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  publicKey: keyPair.publicKey,
  signingKey: keyPair.privateKey,
  extensions: [
    new BasicConstraintsExtension(false, undefined, true),
    new KeyUsagesExtension(
      KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment,
      true,
    ),
    new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth], true),
    new SubjectAlternativeNameExtension(
      [
        { type: "dns", value: "localhost" },
        { type: "dns", value: "corp-wildcard.corp.test" },
        { type: "dns", value: "*.corp.test" },
        { type: "ip", value: "127.0.0.1" },
        { type: "ip", value: "::1" },
      ],
      false,
    ),
    await SubjectKeyIdentifierExtension.create(keyPair.publicKey),
    await AuthorityKeyIdentifierExtension.create(keyPair.publicKey),
  ],
});

const certPem = cert.toString("pem");
writeFileSync(pemPath, certPem.endsWith("\n") ? certPem : certPem + "\n", {
  mode: 0o600,
});

const keyDer = await webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
const keyB64 = Buffer.from(keyDer).toString("base64");
const keyLines = keyB64.match(/.{1,64}/g) ?? [];
const keyPem = [
  "-----BEGIN PRIVATE KEY-----",
  ...keyLines,
  "-----END PRIVATE KEY-----",
  "",
].join("\n");
writeFileSync(keyPath, keyPem, { mode: 0o600 });

const certDer = Buffer.from(cert.rawData);
const thumbSha1 = createHash("sha1").update(certDer).digest("hex").toUpperCase();
const thumbSha256 = createHash("sha256")
  .update(certDer)
  .digest("hex")
  .toUpperCase();

console.log(`Wrote certificate: ${pemPath}`);
console.log(`Wrote private key: ${keyPath}`);
console.log(`SHA-1 thumbprint:   ${thumbSha1}`);
console.log(`SHA-256 thumbprint: ${thumbSha256}`);
console.log("");
console.log("Add this to your VS Code user settings.json:");
console.log("");
console.log(
  JSON.stringify(
    {
      "devcontainerDevCerts.userCertificates": [
        {
          name: "corp-wildcard",
          pemCertPath: pemPath,
          pemKeyPath: keyPath,
          trustInContainer: true,
        },
      ],
      "devcontainerDevCerts.defaultKestrelCertificate": "corp-wildcard",
    },
    null,
    2,
  ),
);
console.log("");
console.log("Then reopen .out/test-project/ in the dev container.");
console.log("");
console.log("Inside a VS Code integrated terminal in the container, verify:");
console.log("  env | grep ASPNETCORE_Kestrel__Certificates__Default");
console.log("    → Path should be ~/.aspnet/dev-certs/https/kestrel-default.pfx");
console.log("  ls -l ~/.aspnet/dev-certs/https/kestrel-default.pfx");
console.log("");
console.log("Run the sample project and confirm Kestrel serves THIS cert:");
console.log("  dotnet run --launch-profile https");
console.log("  curl -kv https://localhost:7001/ 2>&1 | grep -E 'subject:|issuer:'");
console.log(
  `    → subject should be 'CN=corp-wildcard.corp.test...', NOT 'CN=localhost'`,
);
console.log(`    → served cert SHA-1 should match ${thumbSha1}`);
