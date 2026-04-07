using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using DevCerts.Tool.Certificate;

namespace DevCerts.Tool.Platform;

[SupportedOSPlatform("linux")]
internal sealed class LinuxCertificateStore : IPlatformCertificateStore
{
    /// <summary>
    /// .NET X509Store CurrentUser\My path on Linux.
    /// </summary>
    private static string DotNetStorePath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".dotnet", "corefx", "cryptography", "x509stores", "my");

    /// <summary>
    /// OpenSSL trust directory for dev certs.
    /// Honors DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY if set.
    /// </summary>
    private static string OpenSslTrustDir =>
        Environment.GetEnvironmentVariable("DOTNET_DEV_CERTS_OPENSSL_CERTIFICATE_DIRECTORY")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".aspnet", "dev-certs", "trust");

    public X509Certificate2? FindExistingDevCert()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        X509Certificate2? best = null;
        var bestVersion = -1;

        foreach (var cert in store.Certificates)
        {
            if (!CertificateGenerator.IsValidDevCert(cert))
            {
                cert.Dispose();
                continue;
            }

            var version = CertificateGenerator.GetCertificateVersion(cert);
            if (version > bestVersion)
            {
                best?.Dispose();
                best = cert;
                bestVersion = version;
            }
            else
            {
                cert.Dispose();
            }
        }

        return best;
    }

    public void SaveCertificate(X509Certificate2 cert)
    {
        // Re-export and re-import with PersistKeySet to ensure the key is saved
        var pfxBytes = cert.Export(X509ContentType.Pfx);
        using var persistedCert = X509CertificateLoader.LoadPkcs12(
            pfxBytes, null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(persistedCert);
    }

    public void TrustCertificate(X509Certificate2 cert)
    {
        // 1. Trust in .NET's Root store (for X509Chain.Build validation)
        TrustInDotNetRootStore(cert);

        // 2. Trust via OpenSSL directory with hash symlinks
        TrustViaOpenSsl(cert);
    }

    public void RemoveCertificates()
    {
        // Remove from My store
        RemoveDevCertsFromStore(StoreName.My);

        // Remove from Root store
        RemoveDevCertsFromStore(StoreName.Root);

        // Remove OpenSSL trust files
        if (Directory.Exists(OpenSslTrustDir))
        {
            foreach (var file in Directory.GetFiles(OpenSslTrustDir, "aspnetcore-localhost-*"))
                File.Delete(file);
            // Remove hash symlinks
            foreach (var file in Directory.GetFiles(OpenSslTrustDir))
            {
                if (IsHashSymlink(file))
                    File.Delete(file);
            }
        }
    }

    public CertificateStatus CheckStatus()
    {
        using var cert = FindExistingDevCert();
        if (cert is null)
            return new CertificateStatus(false, false, null, null, null, -1);

        var isTrusted = IsTrustedViaOpenSsl(cert);
        var version = CertificateGenerator.GetCertificateVersion(cert);
        return new CertificateStatus(true, isTrusted, cert.Thumbprint,
            cert.NotBefore, cert.NotAfter, version);
    }

    private static void TrustInDotNetRootStore(X509Certificate2 cert)
    {
        var publicCertBytes = cert.Export(X509ContentType.Cert);
        using var publicCert = X509CertificateLoader.LoadCertificate(publicCertBytes);

        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(publicCert);
    }

    private static void TrustViaOpenSsl(X509Certificate2 cert)
    {
        Directory.CreateDirectory(OpenSslTrustDir);

        var pemFileName = $"aspnetcore-localhost-{cert.Thumbprint}.pem";
        var pemPath = Path.Combine(OpenSslTrustDir, pemFileName);

        // Export public cert as PEM
        var certPem = cert.ExportCertificatePem();
        File.WriteAllText(pemPath, certPem);

        // Rehash the directory (simplified c_rehash)
        RehashDirectory(OpenSslTrustDir);
    }

    /// <summary>
    /// Simplified c_rehash implementation matching UnixCertificateManager.
    /// Creates hash-based symlinks for OpenSSL certificate discovery.
    /// </summary>
    internal static void RehashDirectory(string directory)
    {
        // Remove existing hash symlinks
        foreach (var file in Directory.GetFiles(directory))
        {
            if (IsHashSymlink(file))
                File.Delete(file);
        }

        // Create new hash symlinks for all PEM/CRT files
        foreach (var certFile in Directory.GetFiles(directory))
        {
            var ext = Path.GetExtension(certFile).ToLowerInvariant();
            if (ext is not (".pem" or ".crt" or ".cer"))
                continue;

            var hash = GetOpenSslSubjectHash(certFile);
            if (hash is null)
                continue;

            // Find an available slot (hash.0, hash.1, etc.)
            for (var i = 0; i < 10; i++)
            {
                var linkPath = Path.Combine(directory, $"{hash}.{i}");
                if (!File.Exists(linkPath))
                {
                    File.CreateSymbolicLink(linkPath, Path.GetFileName(certFile));
                    break;
                }
            }
        }
    }

    private static string? GetOpenSslSubjectHash(string certPath)
    {
        try
        {
            var psi = new ProcessStartInfo("openssl", $"x509 -hash -noout -in \"{certPath}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var process = Process.Start(psi);
            if (process is null) return null;
            var hash = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();
            return process.ExitCode == 0 ? hash : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsTrustedViaOpenSsl(X509Certificate2 cert)
    {
        var pemPath = Path.Combine(OpenSslTrustDir, $"aspnetcore-localhost-{cert.Thumbprint}.pem");
        return File.Exists(pemPath);
    }

    private static bool IsHashSymlink(string path)
    {
        var fileName = Path.GetFileName(path);
        // Hash symlinks match pattern: 8 hex chars + dot + digit
        return fileName.Length >= 10
               && fileName[8] == '.'
               && char.IsDigit(fileName[9])
               && fileName[..8].All(c => char.IsAsciiHexDigitLower(c));
    }

    private static void RemoveDevCertsFromStore(StoreName storeName)
    {
        using var store = new X509Store(storeName, StoreLocation.CurrentUser);
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
}
