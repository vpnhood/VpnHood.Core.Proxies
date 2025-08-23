namespace VpnHood.Core.Proxies.Socks5Proxy;

public readonly record struct Socks5CommandResult(
    Socks5Command Command,
    Socks5CommandReply Reply,
    Socks5Endpoint BoundEndpoint);
