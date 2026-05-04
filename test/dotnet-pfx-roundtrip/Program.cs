// CI harness invoked from the UI extension's vitest integration tests.
//
// Reads a PFX from disk, loads it via .NET's modern PKCS#12 loader, and
// prints "OK\t{Subject}\t{Thumbprint}" on success. Anything else exits
// non-zero with a "FAIL\t{ExceptionType}\t{Message}" line on stderr so
// the harness driver in TypeScript can surface a useful diagnostic when
// our PFX format drifts away from what .NET accepts.
//
// Usage:  PfxRoundtrip <pfx-path> [password]
//
// The password defaults to the empty string (matching the dev-cert flow).

using System.Security.Cryptography.X509Certificates;

if (args.Length < 1 || args.Length > 2)
{
    Console.Error.WriteLine("usage: PfxRoundtrip <pfx-path> [password]");
    return 2;
}

string pfxPath = args[0];
string password = args.Length > 1 ? args[1] : string.Empty;

try
{
    byte[] bytes = File.ReadAllBytes(pfxPath);

    // X509CertificateLoader.LoadPkcs12 is the non-obsolete replacement for
    // `new X509Certificate2(byte[], string)` introduced in .NET 9. It
    // exercises the same managed PKCS#12 parser that Kestrel's X509Store
    // fallback uses, so success here is a real signal that the format we
    // emit will be readable by ASP.NET / Aspire at runtime.
    using X509Certificate2 cert = X509CertificateLoader.LoadPkcs12(
        bytes,
        password,
        X509KeyStorageFlags.EphemeralKeySet
    );

    Console.WriteLine($"OK\t{cert.Subject}\t{cert.Thumbprint}");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"FAIL\t{ex.GetType().Name}\t{ex.Message}");
    return 1;
}
