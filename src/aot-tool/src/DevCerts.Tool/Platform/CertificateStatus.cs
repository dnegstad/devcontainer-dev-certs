namespace DevCerts.Tool.Platform;

internal record CertificateStatus(
    bool Exists,
    bool IsTrusted,
    string? Thumbprint,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    int Version);
