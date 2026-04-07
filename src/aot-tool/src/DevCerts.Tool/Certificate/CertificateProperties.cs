using System.Net;
using System.Security.Cryptography;

namespace DevCerts.Tool.Certificate;

internal static class CertificateProperties
{
    public const string SubjectName = "CN=localhost";
    public const int RsaKeySize = 2048;
    public static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;
    public static readonly RSASignaturePadding SignaturePadding = RSASignaturePadding.Pkcs1;
    public const int ValidityDays = 365;

    /// <summary>
    /// The OID that identifies a certificate as an ASP.NET Core HTTPS development certificate.
    /// Microsoft private arc: 1.3.6.1.4.1.311 = Microsoft, 84.1.1 = ASP.NET HTTPS dev cert.
    /// </summary>
    public const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";

    public const string AspNetHttpsOidFriendlyName = "ASP.NET Core HTTPS development certificate";

    /// <summary>
    /// Current version of the dev cert format. Stored as a single byte in the custom OID extension.
    /// Version 6 was introduced in .NET SDK 10.0.102 / runtime 10.0.2.
    /// </summary>
    public const byte CurrentCertificateVersion = 6;

    /// <summary>
    /// Minimum version accepted by non-interactive consumers (e.g., first-run experience).
    /// Version 4 was introduced in .NET SDK 10.0.100 / runtime 10.0.0.
    /// </summary>
    public const byte MinimumCertificateVersion = 4;

    public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    public static readonly string[] SanDnsNames =
    [
        "localhost",
        "*.dev.localhost",
        "*.dev.internal",
        "host.docker.internal",
        "host.containers.internal",
    ];

    public static readonly IPAddress[] SanIpAddresses =
    [
        IPAddress.Loopback,     // 127.0.0.1
        IPAddress.IPv6Loopback, // ::1
    ];
}
