import { describe, it, expect } from "vitest";
import { Extension, SubjectAlternativeNameExtension, X509CertificateGenerator, cryptoProvider, } from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import {
  DevCert,
  validateLocalSans,
  ASPNET_HTTPS_OID,
  CURRENT_CERTIFICATE_VERSION,
  SAN_DNS_NAMES,
  SAN_IP_ADDRESSES,
} from "@devcontainer-dev-certs/shared";

cryptoProvider.set(webcrypto as unknown as Crypto);

async function makeCertWithSans(
  sans: { type: "dns" | "ip"; value: string }[]
): Promise<DevCert> {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
  const now = new Date();
  const exp = new Date(now.getTime() + 30 * 86400 * 1000);
  const cert = await X509CertificateGenerator.create({
    serialNumber: "01",
    subject: "CN=localhost",
    issuer: "CN=localhost",
    notBefore: now,
    notAfter: exp,
    signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    extensions: [
      new SubjectAlternativeNameExtension(sans, true),
      new Extension(
        ASPNET_HTTPS_OID,
        false,
        new Uint8Array([CURRENT_CERTIFICATE_VERSION]).buffer
      ),
    ],
  });
  return new DevCert(cert);
}

describe("validateLocalSans", () => {
  it("accepts the canonical ASP.NET dev cert SAN set", async () => {
    const cert = await makeCertWithSans([
      ...SAN_DNS_NAMES.map((dns) => ({ type: "dns" as const, value: dns })),
      ...SAN_IP_ADDRESSES.map((ip) => ({ type: "ip" as const, value: ip })),
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
    expect(result.nonLocalEntries).toHaveLength(0);
  });

  it("rejects a DNS entry outside the local-only set", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "localhost" },
      { type: "dns", value: "example.com" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.nonLocalEntries).toEqual([
      { type: "dns", value: "example.com" },
    ]);
  });

  it("rejects a public IPv4 SAN", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "localhost" },
      { type: "ip", value: "8.8.8.8" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.nonLocalEntries).toEqual([{ type: "ip", value: "8.8.8.8" }]);
  });

  it("accepts private IPv4 ranges (10/8, 172.16/12, 192.168/16, 169.254/16)", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "localhost" },
      { type: "ip", value: "10.1.2.3" },
      { type: "ip", value: "172.20.0.1" },
      { type: "ip", value: "192.168.5.6" },
      { type: "ip", value: "169.254.42.42" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
  });

  it("rejects 172.32.x.x which is OUTSIDE 172.16/12", async () => {
    const cert = await makeCertWithSans([
      { type: "ip", value: "172.32.0.1" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.nonLocalEntries).toEqual([
      { type: "ip", value: "172.32.0.1" },
    ]);
  });

  it("accepts ::1 (IPv6 loopback)", async () => {
    const cert = await makeCertWithSans([{ type: "ip", value: "::1" }]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
  });

  it("accepts fc00::/7 (IPv6 unique local) and fe80::/10 (link-local)", async () => {
    const cert = await makeCertWithSans([
      { type: "ip", value: "fc00::1" },
      { type: "ip", value: "fd12:3456:789a::1" },
      { type: "ip", value: "fe80::1" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
  });

  it("rejects 2001:db8:: (documentation block)", async () => {
    const cert = await makeCertWithSans([
      { type: "ip", value: "2001:db8::1" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
  });

  it("accepts wildcard *.dev.localhost (strips '*.' before checking)", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "*.dev.localhost" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
  });

  it("rejects wildcard *.example.com", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "*.example.com" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.nonLocalEntries).toEqual([
      { type: "dns", value: "*.example.com" },
    ]);
  });

  it("rejects a bare wildcard '*'", async () => {
    const cert = await makeCertWithSans([{ type: "dns", value: "*" }]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
  });

  it("rejects a cert with no SAN extension rather than passing it", async () => {
    // Previously this returned ok — "no entries, so no non-local entries".
    // That reported "SANs are local-only" about a cert whose scope we never
    // established. No genuine dev cert omits SAN (the canonical one carries
    // seven entries) and a cert without one authenticates no hostname to any
    // modern client, so there is nothing legitimate to let through.
    const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );
    const now = new Date();
    const cert = await X509CertificateGenerator.create({
      serialNumber: "01",
      subject: "CN=localhost",
      issuer: "CN=localhost",
      notBefore: now,
      notAfter: new Date(now.getTime() + 86400_000),
      signingAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      publicKey: keyPair.publicKey,
      signingKey: keyPair.privateKey,
      extensions: [],
    });
    const result = validateLocalSans(new DevCert(cert));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing");
  });

  it("reports reason 'non-local' (not a structural failure) for an off-host name", async () => {
    // The call site keys the `allowNonLocalContainerCertSans` override off
    // this reason specifically, so the discrimination has to hold.
    const cert = await makeCertWithSans([
      { type: "dns", value: "evil.example.com" },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("non-local");
    expect(result.nonLocalEntries).toEqual([
      { type: "dns", value: "evil.example.com" },
    ]);
  });

  it("rejects a SAN carrying a GeneralName type other than dNSName / iPAddress", async () => {
    // rfc822Name / uniformResourceIdentifier / directoryName play no part in
    // TLS server identity, so dropping them was defensible — but it meant
    // vouching for a cert we had only partially inspected. A dev cert has no
    // business carrying them.
    const cert = await makeCertWithSans([
      { type: "dns", value: "localhost" },
      { type: "email", value: "a@evil.example.com" },
    ] as never);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("unsupported-entry");
    expect(result.detail).toContain("email");
  });

  it("rejects a SAN whose DER does not decode, without throwing", async () => {
    // `@peculiar/x509` parses extensions lazily and throws from
    // getExtension. That used to escape into the accept handler's blanket
    // catch — fail-closed by accident of the call site. Now it is a reported
    // reason, so a future `try/catch` added inside the scanner cannot
    // silently invert it.
    const cert = await makeCertWithSans([{ type: "dns", value: "localhost" }]);
    const der = Buffer.from(cert.der);
    const needle = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]);
    const idx = der.indexOf(needle);
    expect(idx).toBeGreaterThan(0);
    let p = idx + needle.length;
    if (der[p] === 0x01) p += 3; // skip the critical BOOLEAN
    expect(der[p]).toBe(0x04); // extnValue OCTET STRING
    const contentStart = p + 2;
    const contentLength = der[p + 1];
    der.fill(0x00, contentStart, contentStart + contentLength);
    der[contentStart] = 0x30; // SEQUENCE header over junk
    der[contentStart + 1] = contentLength - 2;

    const result = validateLocalSans(new DevCert(der));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("unparseable");
  });

  it("handles trailing-dot DNS names like 'localhost.'", async () => {
    const cert = await makeCertWithSans([
      { type: "dns", value: "localhost." },
    ]);
    const result = validateLocalSans(cert);
    expect(result.ok).toBe(true);
  });
});
