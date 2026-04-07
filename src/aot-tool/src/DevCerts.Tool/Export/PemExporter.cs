using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DevCerts.Tool.Export;

internal static class PemExporter
{
    /// <summary>
    /// Export a certificate as PEM files (cert + private key).
    /// Returns (certPath, keyPath).
    /// </summary>
    public static (string CertPath, string KeyPath) Export(X509Certificate2 cert, string outputDir)
    {
        Directory.CreateDirectory(outputDir);

        var certPath = Path.Combine(outputDir, "aspnetcore-dev.pem");
        var keyPath = Path.Combine(outputDir, "aspnetcore-dev.key");

        // Export certificate as PEM
        var certPem = cert.ExportCertificatePem();
        File.WriteAllText(certPath, certPem);

        // Export private key as unencrypted PKCS8 PEM
        var rsa = cert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate does not have an RSA private key.");
        var keyPem = rsa.ExportPkcs8PrivateKeyPem();
        File.WriteAllText(keyPath, keyPem);

        return (certPath, keyPath);
    }
}
