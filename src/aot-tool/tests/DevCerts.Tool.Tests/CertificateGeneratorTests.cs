using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DevCerts.Tool.Certificate;
using Xunit;

namespace DevCerts.Tool.Tests;

public class CertificateGeneratorTests
{
    [Fact]
    public void GenerateCertificate_HasCorrectSubject()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        Assert.Equal("CN=localhost", cert.Subject);
    }

    [Fact]
    public void GenerateCertificate_Is2048BitRsa()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var rsa = cert.GetRSAPrivateKey();
        Assert.NotNull(rsa);
        Assert.Equal(2048, rsa.KeySize);
    }

    [Fact]
    public void GenerateCertificate_HasAspNetCoreOid()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var extension = cert.Extensions[CertificateProperties.AspNetHttpsOid];
        Assert.NotNull(extension);
        Assert.False(extension.Critical);
    }

    [Fact]
    public void GenerateCertificate_HasCorrectVersion()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var version = CertificateGenerator.GetCertificateVersion(cert);
        Assert.Equal(CertificateProperties.CurrentCertificateVersion, version);
    }

    [Fact]
    public void GenerateCertificate_HasCorrectBasicConstraints()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(bc.Critical);
        Assert.False(bc.CertificateAuthority);
    }

    [Fact]
    public void GenerateCertificate_HasCorrectKeyUsage()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.True(ku.Critical);
        Assert.True(ku.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment));
        Assert.True(ku.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature));
    }

    [Fact]
    public void GenerateCertificate_HasServerAuthEku()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.True(eku.Critical);
        Assert.Contains(eku.EnhancedKeyUsages.Cast<Oid>(),
            o => o.Value == CertificateProperties.ServerAuthenticationOid);
    }

    [Fact]
    public void GenerateCertificate_HasCorrectSan()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        Assert.True(san.Critical);

        var dnsNames = san.EnumerateDnsNames().ToList();
        foreach (var expected in CertificateProperties.SanDnsNames)
        {
            Assert.Contains(expected, dnsNames);
        }

        var ips = san.EnumerateIPAddresses().ToList();
        Assert.Contains(ips, ip => ip.Equals(IPAddress.Loopback));
        Assert.Contains(ips, ip => ip.Equals(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void GenerateCertificate_ValidForOneYear()
    {
        var now = DateTimeOffset.UtcNow;
        using var cert = CertificateGenerator.GenerateCertificate(notBefore: now, notAfter: now.AddDays(365));

        Assert.Equal(now.UtcDateTime.Date, cert.NotBefore.ToUniversalTime().Date);

        var expectedExpiry = now.AddDays(365).UtcDateTime.Date;
        Assert.Equal(expectedExpiry, cert.NotAfter.ToUniversalTime().Date);
    }

    [Fact]
    public void GenerateCertificate_HasSubjectKeyIdentifier()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        var ski = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
        Assert.NotNull(ski);
        Assert.False(ski.Critical);
    }

    [Fact]
    public void GenerateCertificate_HasAuthorityKeyIdentifier()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        // AKI OID is 2.5.29.35
        var aki = cert.Extensions["2.5.29.35"];
        Assert.NotNull(aki);
        Assert.False(aki.Critical);
    }

    [Fact]
    public void GenerateCertificate_HasExportablePrivateKey()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        Assert.True(cert.HasPrivateKey);
        var rsa = cert.GetRSAPrivateKey()!;
        // Should be able to export the private key
        var exported = rsa.ExportPkcs8PrivateKey();
        Assert.NotEmpty(exported);
    }

    [Fact]
    public void IsValidDevCert_ReturnsTrueForGeneratedCert()
    {
        using var cert = CertificateGenerator.GenerateCertificate();
        Assert.True(CertificateGenerator.IsValidDevCert(cert));
    }

    [Fact]
    public void IsValidDevCert_ReturnsFalseForWrongSubject()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=notlocalhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509Extension(
            new Oid(CertificateProperties.AspNetHttpsOid),
            [CertificateProperties.CurrentCertificateVersion],
            critical: false));
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(365));
        Assert.False(CertificateGenerator.IsValidDevCert(cert));
    }

    [Fact]
    public void GetCertificateVersion_ReturnsNegativeOneForNonDevCert()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(365));
        Assert.Equal(-1, CertificateGenerator.GetCertificateVersion(cert));
    }
}
