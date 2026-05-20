import { describe, it, expect } from "vitest";
import type {
  CertMaterial,
  CertMaterialV2,
} from "@devcontainer-dev-certs/shared";
import { upmapV1ToV3, upmapV2ToV3 } from "../src/util/upmap";

const PEM_CERT_B64 = Buffer.from(
  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
).toString("base64");
const PEM_KEY_B64 = Buffer.from(
  "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n"
).toString("base64");

describe("upmapV2ToV3", () => {
  it("preserves V2 wire behavior — installs to store when a PFX is present", () => {
    const v2: CertMaterialV2 = {
      kind: "user",
      name: "corp",
      thumbprint: "ABCDEF",
      pfxBase64: Buffer.from("PASSWORDLESS").toString("base64"),
      pemCertBase64: PEM_CERT_B64,
      pemKeyBase64: PEM_KEY_B64,
      rootPfxBase64: Buffer.from("ROOT").toString("base64"),
      trustInContainer: true,
    };
    const v3 = upmapV2ToV3(v2);
    // V2 was always passwordless and always store-bound; on V3 that's an
    // implicit `installToDotNetStore: true` and `dotNetStorePfxBase64`
    // equal to `pfxBase64`.
    expect(v3.installToDotNetStore).toBe(true);
    expect(v3.dotNetStorePfxBase64).toBe(v2.pfxBase64);
    expect(v3.pfxBase64).toBe(v2.pfxBase64);
    // Pass-through fields.
    expect(v3.kind).toBe("user");
    expect(v3.thumbprint).toBe("ABCDEF");
    expect(v3.trustInContainer).toBe(true);
    expect(v3.rootPfxBase64).toBe(v2.rootPfxBase64);
  });

  it("skips store install when V2 carried no PFX (CA-only entry)", () => {
    const v2: CertMaterialV2 = {
      kind: "user",
      name: "ca-only",
      thumbprint: "ABCDEF",
      pemCertBase64: PEM_CERT_B64,
      trustInContainer: true,
    };
    const v3 = upmapV2ToV3(v2);
    expect(v3.installToDotNetStore).toBe(false);
    expect(v3.dotNetStorePfxBase64).toBeUndefined();
    expect(v3.pfxBase64).toBeUndefined();
  });

  it("propagates dotnet-dev kind unchanged", () => {
    const v2: CertMaterialV2 = {
      kind: "dotnet-dev",
      name: "aspnetcore-dev",
      thumbprint: "DEADBEEF",
      pfxBase64: Buffer.from("DEV-PFX").toString("base64"),
      pemCertBase64: PEM_CERT_B64,
      pemKeyBase64: PEM_KEY_B64,
      rootPfxBase64: Buffer.from("DEV-ROOT").toString("base64"),
      trustInContainer: true,
    };
    const v3 = upmapV2ToV3(v2);
    expect(v3.kind).toBe("dotnet-dev");
    expect(v3.installToDotNetStore).toBe(true);
  });
});

describe("upmapV1ToV3", () => {
  it("treats the legacy dotnet-dev cert as always-install-to-store", () => {
    const v1: CertMaterial = {
      thumbprint: "DEADBEEF",
      pfxBase64: Buffer.from("DEV-PFX").toString("base64"),
      pemCertBase64: PEM_CERT_B64,
      pemKeyBase64: PEM_KEY_B64,
      rootPfxBase64: Buffer.from("DEV-ROOT").toString("base64"),
    };
    const v3 = upmapV1ToV3(v1);
    expect(v3.kind).toBe("dotnet-dev");
    expect(v3.name).toBe("aspnetcore-dev");
    expect(v3.installToDotNetStore).toBe(true);
    expect(v3.dotNetStorePfxBase64).toBe(v1.pfxBase64);
    expect(v3.trustInContainer).toBe(true);
  });
});
