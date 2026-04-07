using System.Text.Json.Serialization;
using DevCerts.Tool.Platform;

namespace DevCerts.Tool;

[JsonSerializable(typeof(CertificateStatus))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
internal partial class JsonContext : JsonSerializerContext;
