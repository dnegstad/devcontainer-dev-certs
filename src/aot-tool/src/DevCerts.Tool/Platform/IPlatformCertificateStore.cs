using System.Security.Cryptography.X509Certificates;

namespace DevCerts.Tool.Platform;

internal interface IPlatformCertificateStore
{
    /// <summary>
    /// Find an existing valid ASP.NET dev cert in the platform store.
    /// </summary>
    X509Certificate2? FindExistingDevCert();

    /// <summary>
    /// Save a certificate (with private key) to the platform store.
    /// </summary>
    void SaveCertificate(X509Certificate2 cert);

    /// <summary>
    /// Trust a certificate so the OS/browser accepts it.
    /// </summary>
    void TrustCertificate(X509Certificate2 cert);

    /// <summary>
    /// Remove dev certificates from all stores.
    /// </summary>
    void RemoveCertificates();

    /// <summary>
    /// Check the status of the dev certificate.
    /// </summary>
    CertificateStatus CheckStatus();

    /// <summary>
    /// Create the appropriate store for the current platform.
    /// </summary>
    static IPlatformCertificateStore Create()
    {
        if (OperatingSystem.IsWindows())
            return new WindowsCertificateStore();
        if (OperatingSystem.IsMacOS())
            return new MacOsCertificateStore();
        if (OperatingSystem.IsLinux())
            return new LinuxCertificateStore();
        throw new PlatformNotSupportedException("Unsupported operating system.");
    }
}
