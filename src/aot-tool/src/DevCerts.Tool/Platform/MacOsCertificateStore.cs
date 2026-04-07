using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using DevCerts.Tool.Certificate;

namespace DevCerts.Tool.Platform;

[SupportedOSPlatform("macos")]
internal sealed class MacOsCertificateStore : IPlatformCertificateStore
{
    private static string DevCertsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aspnet", "dev-certs", "https");

    public X509Certificate2? FindExistingDevCert()
    {
        // Check disk storage first
        if (Directory.Exists(DevCertsDir))
        {
            foreach (var pfxFile in Directory.GetFiles(DevCertsDir, "aspnetcore-localhost-*.pfx"))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadPkcs12FromFile(pfxFile, null,
                        X509KeyStorageFlags.Exportable);
                    if (CertificateGenerator.IsValidDevCert(cert))
                        return cert;
                    cert.Dispose();
                }
                catch
                {
                    // Skip invalid PFX files
                }
            }
        }

        // Fallback to X509Store
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates)
        {
            if (CertificateGenerator.IsValidDevCert(cert))
                return cert;
            cert.Dispose();
        }

        return null;
    }

    public void SaveCertificate(X509Certificate2 cert)
    {
        // Save to disk
        Directory.CreateDirectory(DevCertsDir);
        var pfxPath = Path.Combine(DevCertsDir, $"aspnetcore-localhost-{cert.Thumbprint}.pfx");
        var pfxBytes = cert.Export(X509ContentType.Pfx);
        File.WriteAllBytes(pfxPath, pfxBytes);

        // Also add to X509Store for .NET runtime discovery
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
    }

    public void TrustCertificate(X509Certificate2 cert)
    {
        // Export public cert to temp file
        var tempCertPath = Path.GetTempFileName();
        try
        {
            var certBytes = cert.Export(X509ContentType.Cert);
            File.WriteAllBytes(tempCertPath, certBytes);

            var keychainPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Keychains", "login.keychain-db");

            var result = RunProcess("security", $"add-trusted-cert -p basic -p ssl -k \"{keychainPath}\" \"{tempCertPath}\"");
            if (result.ExitCode != 0)
                throw new InvalidOperationException($"Failed to trust certificate: {result.StdErr}");
        }
        finally
        {
            File.Delete(tempCertPath);
        }
    }

    public void RemoveCertificates()
    {
        // Remove trust entries and certs from the login keychain
        RemoveFromKeychain();

        // Remove from disk
        if (Directory.Exists(DevCertsDir))
        {
            foreach (var pfxFile in Directory.GetFiles(DevCertsDir, "aspnetcore-localhost-*.pfx"))
            {
                File.Delete(pfxFile);
            }
        }

        // Remove from X509Store
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var toRemove = new List<X509Certificate2>();
        foreach (var cert in store.Certificates)
        {
            if (cert.Extensions[CertificateProperties.AspNetHttpsOid] is not null)
                toRemove.Add(cert);
            else
                cert.Dispose();
        }
        foreach (var cert in toRemove)
        {
            store.Remove(cert);
            cert.Dispose();
        }
    }

    private static void RemoveFromKeychain()
    {
        var keychainPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library", "Keychains", "login.keychain-db");

        // Find and remove all localhost certs that match the dev cert pattern.
        // security delete-certificate -c matches on the common name.
        // Loop because there may be multiple from prior generations.
        for (var i = 0; i < 10; i++)
        {
            var result = RunProcess("security",
                $"delete-certificate -c localhost \"{keychainPath}\"");
            if (result.ExitCode != 0)
                break; // No more matching certs
        }

        // Also remove trust settings for localhost certs
        RunProcess("security",
            $"remove-trusted-cert -d \"{keychainPath}\"");
    }

    public CertificateStatus CheckStatus()
    {
        using var cert = FindExistingDevCert();
        if (cert is null)
            return new CertificateStatus(false, false, null, null, null, -1);

        var isTrusted = CheckTrust(cert);
        var version = CertificateGenerator.GetCertificateVersion(cert);
        return new CertificateStatus(true, isTrusted, cert.Thumbprint,
            cert.NotBefore, cert.NotAfter, version);
    }

    private static bool CheckTrust(X509Certificate2 cert)
    {
        var tempCertPath = Path.GetTempFileName();
        try
        {
            var certBytes = cert.Export(X509ContentType.Cert);
            File.WriteAllBytes(tempCertPath, certBytes);
            var result = RunProcess("security", $"verify-cert -c \"{tempCertPath}\" -p ssl");
            return result.ExitCode == 0;
        }
        finally
        {
            File.Delete(tempCertPath);
        }
    }

    private static (int ExitCode, string StdOut, string StdErr) RunProcess(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout, stderr);
    }
}
