using VpnHood.Core.Proxies.Socks5Proxy;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public readonly struct Socks5HandshakeResult
{
    public Socks5AuthenticationType AuthType { get; init; }
    public RequestHeader RequestHeader { get; init; }
    public bool IsValid { get; init; }

    public static Socks5HandshakeResult Invalid => new() { IsValid = false };

    public static Socks5HandshakeResult Valid(Socks5AuthenticationType authType, RequestHeader requestHeader)
    {
        return new Socks5HandshakeResult
        {
            AuthType = authType,
            RequestHeader = requestHeader,
            IsValid = true
        };
    }
}