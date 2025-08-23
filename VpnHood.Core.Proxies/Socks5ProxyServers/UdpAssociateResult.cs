using System.Net;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public sealed class UdpAssociateResult
{
    public required IPAddress BindAddress { get; init; }
    public required int BindPort { get; init; }
}