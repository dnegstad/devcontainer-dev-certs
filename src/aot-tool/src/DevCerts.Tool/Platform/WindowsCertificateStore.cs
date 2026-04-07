using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using DevCerts.Tool.Certificate;

namespace DevCerts.Tool.Platform;

[SupportedOSPlatform("windows")]
internal sealed class WindowsCertificateStore : IPlatformCertificateStore
{
    public X509Certificate2? FindExistingDevCert()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return FindDevCertInCollection(store.Certificates);
    }

    public void SaveCertificate(X509Certificate2 cert)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
    }

    public void TrustCertificate(X509Certificate2 cert)
    {
        // Export public cert only (no private key) for the trust store
        var publicCertBytes = cert.Export(X509ContentType.Cert);
        using var publicCert = X509CertificateLoader.LoadCertificate(publicCertBytes);

        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(publicCert);
    }

    public void RemoveCertificates()
    {
        RemoveFromStore(StoreName.My);
        RemoveFromStore(StoreName.Root);
    }

    public CertificateStatus CheckStatus()
    {
        using var cert = FindExistingDevCert();
        if (cert is null)
            return new CertificateStatus(false, false, null, null, null, -1);

        var isTrusted = IsTrustedInRootStore(cert);
        var version = CertificateGenerator.GetCertificateVersion(cert);
        return new CertificateStatus(true, isTrusted, cert.Thumbprint,
            cert.NotBefore, cert.NotAfter, version);
    }

    private static bool IsTrustedInRootStore(X509Certificate2 cert)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
        return found.Count > 0;
    }

    private static void RemoveFromStore(StoreName storeName)
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

    private static X509Certificate2? FindDevCertInCollection(X509Certificate2Collection certs)
    {
        X509Certificate2? best = null;
        var bestVersion = -1;

        foreach (var cert in certs)
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
}
