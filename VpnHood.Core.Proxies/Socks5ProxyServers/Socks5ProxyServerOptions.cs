using System.Net;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public class Socks5ProxyServerOptions
{
    public required IPEndPoint ListenEndPoint { get; init; }

    public string? Username { get; init; }
    public string? Password { get; init; }
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan HostConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// After one tunnel direction reaches EOF (TCP half-close), how long the other direction
    /// may keep draining before the tunnel is torn down. Bounds how long an idle peer can
    /// retain a tunnel's buffers, sockets and handler state.
    /// </summary>
    public TimeSpan TunnelHalfCloseTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public int Backlog { get; init; } = 512;

    /// <summary>
    /// Hard cap on concurrent client connections; connections beyond it are accepted and
    /// immediately closed. Unlimited by default — memory-constrained hosts (e.g. a mobile
    /// network extension) should set an explicit cap sized to their budget.
    /// </summary>
    public int MaxConnections { get; init; } = int.MaxValue;
}
