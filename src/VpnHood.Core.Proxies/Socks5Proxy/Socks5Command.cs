namespace VpnHood.Core.Proxies.Socks5Proxy;

public enum Socks5Command : byte
{
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03
}