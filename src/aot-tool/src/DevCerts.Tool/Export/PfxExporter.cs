using System.Security.Cryptography.X509Certificates;

namespace DevCerts.Tool.Export;

internal static class PfxExporter
{
    /// <summary>
    /// Export a certificate (with private key) as a PFX/PKCS12 file.
    /// </summary>
    public static string Export(X509Certificate2 cert, string outputDir, string? password = null)
    {
        Directory.CreateDirectory(outputDir);
        var path = Path.Combine(outputDir, "aspnetcore-dev.pfx");
        var bytes = cert.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(path, bytes);
        return path;
    }
}
