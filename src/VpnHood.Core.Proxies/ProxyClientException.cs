using System.Net.Sockets;

namespace VpnHood.Core.Proxies;

public class ProxyClientException(SocketError socketError, string? message = null)
    : SocketException((int)socketError, message);
