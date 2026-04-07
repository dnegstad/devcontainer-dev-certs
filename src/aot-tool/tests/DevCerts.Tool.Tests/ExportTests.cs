using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DevCerts.Tool.Certificate;
using DevCerts.Tool.Export;
using Xunit;

namespace DevCerts.Tool.Tests;

public class ExportTests : IDisposable
{
    private readonly string _tempDir;
    private readonly X509Certificate2 _cert;

    public ExportTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "devcerts-test-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        _cert = CertificateGenerator.GenerateCertificate();
    }

    public void Dispose()
    {
        _cert.Dispose();
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    [Fact]
    public void PfxExport_ProducesValidPfx()
    {
        var password = "test-password";
        var path = PfxExporter.Export(_cert, _tempDir, password);

        Assert.True(File.Exists(path));
        Assert.EndsWith(".pfx", path);

        // Re-import and verify
        using var reimported = X509CertificateLoader.LoadPkcs12FromFile(path, password);
        Assert.Equal(_cert.Thumbprint, reimported.Thumbprint);
        Assert.True(reimported.HasPrivateKey);
    }

    [Fact]
    public void PfxExport_WorksWithoutPassword()
    {
        var path = PfxExporter.Export(_cert, _tempDir);

        Assert.True(File.Exists(path));

        using var reimported = X509CertificateLoader.LoadPkcs12FromFile(path, null);
        Assert.Equal(_cert.Thumbprint, reimported.Thumbprint);
    }

    [Fact]
    public void PemExport_ProducesCertAndKey()
    {
        var (certPath, keyPath) = PemExporter.Export(_cert, _tempDir);

        Assert.True(File.Exists(certPath));
        Assert.True(File.Exists(keyPath));
        Assert.EndsWith(".pem", certPath);
        Assert.EndsWith(".key", keyPath);
    }

    [Fact]
    public void PemExport_CertHasCorrectPemHeaders()
    {
        var (certPath, _) = PemExporter.Export(_cert, _tempDir);
        var content = File.ReadAllText(certPath);
        Assert.Contains("-----BEGIN CERTIFICATE-----", content);
        Assert.Contains("-----END CERTIFICATE-----", content);
    }

    [Fact]
    public void PemExport_KeyHasCorrectPemHeaders()
    {
        var (_, keyPath) = PemExporter.Export(_cert, _tempDir);
        var content = File.ReadAllText(keyPath);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", content);
        Assert.Contains("-----END PRIVATE KEY-----", content);
    }

    [Fact]
    public void PemExport_KeyMatchesCertificate()
    {
        var (certPath, keyPath) = PemExporter.Export(_cert, _tempDir);

        // Load the PEM cert and key separately, verify they match
        var certPem = File.ReadAllText(certPath);
        var keyPem = File.ReadAllText(keyPath);

        using var reimportedCert = X509Certificate2.CreateFromPem(certPem, keyPem);
        Assert.Equal(_cert.Thumbprint, reimportedCert.Thumbprint);
        Assert.True(reimportedCert.HasPrivateKey);

        // Verify we can sign and verify with the reimported key pair
        using var rsa = reimportedCert.GetRSAPrivateKey()!;
        var data = "test data"u8.ToArray();
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using var pubKey = _cert.GetRSAPublicKey()!;
        Assert.True(pubKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
}
