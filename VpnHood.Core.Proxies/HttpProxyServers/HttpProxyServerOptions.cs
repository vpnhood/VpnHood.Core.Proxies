using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public class HttpProxyServerOptions
{
    public required IPEndPoint ListenEndPoint { get; init; }

    public string? Username { get; init; }
    public string? Password { get; init; }

    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan HostConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);
    public int Backlog { get; init; } = 512;

    // For HTTPS proxy server (TLS between client and proxy)
    public X509Certificate2? ServerCertificate { get; init; }
}