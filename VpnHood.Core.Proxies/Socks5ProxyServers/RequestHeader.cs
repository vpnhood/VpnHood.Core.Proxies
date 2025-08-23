using VpnHood.Core.Proxies.Socks5ProxyClients;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public sealed class RequestHeader
{
    public required Socks5Command Command { get; init; }
    public required Socks5AddressType AddressType { get; init; }
}