import type {
  CertMaterial,
  CertMaterialV2,
  CertMaterialV3,
} from "@devcontainer-dev-certs/shared";

/**
 * V2 → V3 upmap. The V2 wire contract was "passwordless `pfxBase64` always,
 * always written to the .NET X509Store." We carry that forward: any cert
 * that came across V2 with a PFX still gets installed to the store (so
 * existing workflows on an older host extension keep working), and the
 * same passwordless bytes serve as both `pfxBase64` and the store payload.
 * The V3 consent contract only kicks in when both peers speak V3.
 */
export function upmapV2ToV3(material: CertMaterialV2): CertMaterialV3 {
  return {
    kind: material.kind,
    name: material.name,
    thumbprint: material.thumbprint,
    pfxBase64: material.pfxBase64,
    pemCertBase64: material.pemCertBase64,
    pemKeyBase64: material.pemKeyBase64,
    rootPfxBase64: material.rootPfxBase64,
    trustInContainer: material.trustInContainer,
    installToDotNetStore: material.pfxBase64 !== undefined,
    dotNetStorePfxBase64: material.pfxBase64,
  };
}

/**
 * V1 → V3 upmap. V1 only ever returned the auto-generated dotnet-dev cert.
 * That cert always installs to the .NET store — canonical location, no
 * password either way.
 */
export function upmapV1ToV3(legacy: CertMaterial): CertMaterialV3 {
  return {
    kind: "dotnet-dev",
    name: "aspnetcore-dev",
    thumbprint: legacy.thumbprint,
    pfxBase64: legacy.pfxBase64,
    pemCertBase64: legacy.pemCertBase64,
    pemKeyBase64: legacy.pemKeyBase64,
    rootPfxBase64: legacy.rootPfxBase64,
    trustInContainer: true,
    installToDotNetStore: true,
    dotNetStorePfxBase64: legacy.pfxBase64,
  };
}
