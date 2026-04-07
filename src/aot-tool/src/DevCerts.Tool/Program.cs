using System.CommandLine;
using System.Text.Json;
using DevCerts.Tool.Certificate;
using DevCerts.Tool.Export;
using DevCerts.Tool.Platform;

namespace DevCerts.Tool;

internal class Program
{
    static int Main(string[] args)
    {
        var rootCommand = new RootCommand("ASP.NET Core HTTPS development certificate management tool");

        // --- generate ---
        var generateCommand = new Command("generate", "Generate a new development certificate");
        var forceOption = new Option<bool>("--force") { Description = "Replace existing certificate even if valid" };
        generateCommand.Add(forceOption);
        generateCommand.SetAction((parseResult) =>
        {
            var force = parseResult.GetValue(forceOption);
            var store = IPlatformCertificateStore.Create();

            if (!force)
            {
                var existing = store.FindExistingDevCert();
                if (existing is not null)
                {
                    Console.WriteLine($"Valid certificate already exists. Thumbprint: {existing.Thumbprint}");
                    existing.Dispose();
                    return;
                }
            }
            else
            {
                store.RemoveCertificates();
            }

            using var cert = CertificateGenerator.GenerateCertificate();
            store.SaveCertificate(cert);
            Console.WriteLine($"Certificate generated. Thumbprint: {cert.Thumbprint}");
            Console.WriteLine($"Valid until: {cert.NotAfter:yyyy-MM-dd}");
        });

        // --- trust ---
        var trustCommand = new Command("trust", "Trust the development certificate, generating one if it does not exist");
        trustCommand.SetAction((_) =>
        {
            var store = IPlatformCertificateStore.Create();
            var cert = store.FindExistingDevCert();
            if (cert is null)
            {
                cert = CertificateGenerator.GenerateCertificate();
                store.SaveCertificate(cert);
                Console.WriteLine($"Certificate generated. Thumbprint: {cert.Thumbprint}");
            }
            using (cert)
            {
                store.TrustCertificate(cert);
                Console.WriteLine($"Certificate trusted. Thumbprint: {cert.Thumbprint}");
            }
        });

        // --- export ---
        var exportCommand = new Command("export", "Export the development certificate");
        var formatOption = new Option<string>("--format") { Description = "Export format: pfx or pem", Required = true };
        formatOption.AcceptOnlyFromAmong("pfx", "pem");
        var outputOption = new Option<string>("--output") { Description = "Output directory", Required = true };
        var passwordOption = new Option<string?>("--password") { Description = "Password for PFX export" };
        exportCommand.Add(formatOption);
        exportCommand.Add(outputOption);
        exportCommand.Add(passwordOption);
        exportCommand.SetAction((parseResult) =>
        {
            var format = parseResult.GetValue(formatOption)!;
            var output = parseResult.GetValue(outputOption)!;
            var password = parseResult.GetValue(passwordOption);

            var store = IPlatformCertificateStore.Create();
            var cert = store.FindExistingDevCert();
            if (cert is null)
            {
                Console.Error.WriteLine("No development certificate found. Run 'generate' first.");
                Environment.ExitCode = 1;
                return;
            }

            using (cert)
            {
                if (format == "pfx")
                {
                    var path = PfxExporter.Export(cert, output, password);
                    Console.WriteLine($"PFX exported to: {path}");
                }
                else
                {
                    var (certPath, keyPath) = PemExporter.Export(cert, output);
                    Console.WriteLine($"Certificate exported to: {certPath}");
                    Console.WriteLine($"Private key exported to: {keyPath}");
                }
            }
        });

        // --- check ---
        var checkCommand = new Command("check", "Check the development certificate status");
        var jsonOption = new Option<bool>("--json") { Description = "Output as JSON for machine consumption" };
        checkCommand.Add(jsonOption);
        checkCommand.SetAction((parseResult) =>
        {
            var asJson = parseResult.GetValue(jsonOption);
            var store = IPlatformCertificateStore.Create();
            var status = store.CheckStatus();

            if (asJson)
            {
                var json = JsonSerializer.Serialize(status, JsonContext.Default.CertificateStatus);
                Console.WriteLine(json);
            }
            else
            {
                if (!status.Exists)
                {
                    Console.WriteLine("No development certificate found.");
                }
                else
                {
                    Console.WriteLine($"Thumbprint: {status.Thumbprint}");
                    Console.WriteLine($"Valid from: {status.NotBefore:yyyy-MM-dd} to {status.NotAfter:yyyy-MM-dd}");
                    Console.WriteLine($"Trusted:    {(status.IsTrusted ? "Yes" : "No")}");
                    Console.WriteLine($"Version:    {status.Version}");
                }
            }
        });

        // --- clean ---
        var cleanCommand = new Command("clean", "Remove the development certificate");
        cleanCommand.SetAction((_) =>
        {
            var store = IPlatformCertificateStore.Create();
            store.RemoveCertificates();
            Console.WriteLine("Development certificates removed.");
        });

        rootCommand.Add(generateCommand);
        rootCommand.Add(trustCommand);
        rootCommand.Add(exportCommand);
        rootCommand.Add(checkCommand);
        rootCommand.Add(cleanCommand);

        return rootCommand.Parse(args).Invoke();
    }
}
