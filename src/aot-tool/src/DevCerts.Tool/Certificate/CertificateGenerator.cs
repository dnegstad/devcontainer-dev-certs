using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DevCerts.Tool.Certificate;

internal static class CertificateGenerator
{
    public static X509Certificate2 GenerateCertificate(DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
    {
        var now = notBefore ?? DateTimeOffset.UtcNow;
        var expiry = notAfter ?? now.AddDays(CertificateProperties.ValidityDays);

        using var key = RSA.Create(CertificateProperties.RsaKeySize);

        var request = new CertificateRequest(
            CertificateProperties.SubjectName,
            key,
            CertificateProperties.HashAlgorithm,
            CertificateProperties.SignaturePadding);

        // 1. Basic Constraints (critical) — not a CA
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));

        // 2. Key Usage (critical) — KeyEncipherment | DigitalSignature
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                critical: true));

        // 3. Enhanced Key Usage (critical) — Server Authentication
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [new Oid(CertificateProperties.ServerAuthenticationOid)],
                critical: true));

        // 4. Subject Alternative Names (critical)
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dns in CertificateProperties.SanDnsNames)
        {
            sanBuilder.AddDnsName(dns);
        }
        foreach (var ip in CertificateProperties.SanIpAddresses)
        {
            sanBuilder.AddIpAddress(ip);
        }
        request.CertificateExtensions.Add(sanBuilder.Build(critical: true));

        // 5. ASP.NET Core HTTPS Dev Cert marker (non-critical) — version byte
        request.CertificateExtensions.Add(
            new X509Extension(
                new Oid(CertificateProperties.AspNetHttpsOid, CertificateProperties.AspNetHttpsOidFriendlyName),
                [CertificateProperties.CurrentCertificateVersion],
                critical: false));

        // Create self-signed certificate first, then extract SKI/AKI from it
        var tempCert = request.CreateSelfSigned(now, expiry);

        // We need to rebuild with SKI and AKI. Extract the public key info for SKI computation.
        // Use a simpler approach: create the cert, then add SKI/AKI in a second pass via rebuild.
        // Actually, for self-signed certs the SKI and AKI are derived from the public key.
        // .NET's CertificateRequest supports adding them before signing.

        // Reset and rebuild with SKI/AKI
        tempCert.Dispose();
        request = new CertificateRequest(
            CertificateProperties.SubjectName,
            key,
            CertificateProperties.HashAlgorithm,
            CertificateProperties.SignaturePadding);

        // Re-add all extensions
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [new Oid(CertificateProperties.ServerAuthenticationOid)],
                critical: true));
        request.CertificateExtensions.Add(sanBuilder.Build(critical: true));
        request.CertificateExtensions.Add(
            new X509Extension(
                new Oid(CertificateProperties.AspNetHttpsOid, CertificateProperties.AspNetHttpsOidFriendlyName),
                [CertificateProperties.CurrentCertificateVersion],
                critical: false));

        // 6. Subject Key Identifier — compute from public key
        var skiValue = SHA256.HashData(key.ExportSubjectPublicKeyInfo());
        var skiExtension = new X509SubjectKeyIdentifierExtension(skiValue, critical: false);
        request.CertificateExtensions.Add(skiExtension);

        // 7. Authority Key Identifier (self-referencing)
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(skiExtension));

        var cert = request.CreateSelfSigned(now, expiry);

        // Re-import via PFX round-trip to properly associate the private key.
        // This is necessary on Windows where the transient key needs to be persisted.
        var pfxBytes = cert.Export(X509ContentType.Pfx);
        var result = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        return result;
    }

    /// <summary>
    /// Check if a certificate is a valid ASP.NET Core HTTPS development certificate.
    /// </summary>
    public static bool IsValidDevCert(X509Certificate2 cert, byte minimumVersion = CertificateProperties.MinimumCertificateVersion)
    {
        if (cert.Subject != CertificateProperties.SubjectName)
            return false;

        if (cert.NotBefore > DateTimeOffset.UtcNow || cert.NotAfter < DateTimeOffset.UtcNow)
            return false;

        var version = GetCertificateVersion(cert);
        if (version < 0 || version < minimumVersion)
            return false;

        return true;
    }

    /// <summary>
    /// Extract the version number from the ASP.NET dev cert OID extension.
    /// Returns -1 if the certificate does not have the extension.
    /// </summary>
    public static int GetCertificateVersion(X509Certificate2 cert)
    {
        var extension = cert.Extensions[CertificateProperties.AspNetHttpsOid];
        if (extension is null)
            return -1;

        var rawData = extension.RawData;

        // Legacy cert (version 0): raw data is the ASCII-encoded friendly name, or empty
        if (rawData.Length == 0)
            return 0;

        if (rawData.Length == CertificateProperties.AspNetHttpsOidFriendlyName.Length
            && rawData[0] == (byte)'A')
            return 0;

        // Current format: single byte containing the version number
        return rawData[0];
    }
}
