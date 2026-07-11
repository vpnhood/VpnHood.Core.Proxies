using System.Net;

namespace VpnHood.Core.Proxies.HttpProxyClients;

public class HttpProxyClientOptions
{
    public required IPEndPoint ProxyEndPoint { get; init; }
    public string? ProxyHost { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public bool UseTls { get; init; }
    public bool AllowInvalidCertificates { get; init; }
    public IReadOnlyDictionary<string, string>? ExtraHeaders { get; init; }
}
