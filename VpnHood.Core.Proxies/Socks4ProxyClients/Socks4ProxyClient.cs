using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnHood.Core.Proxies.Socks4ProxyClients;

// Minimal SOCKS4/4a client supporting CONNECT only
public class Socks4ProxyClient(Socks4ProxyClientOptions options) : IProxyClient
{
    public IPEndPoint ProxyEndPoint => options.ProxyEndPoint;

    public Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.AddressFamily == AddressFamily.InterNetworkV6)
            throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");

        return ConnectAsync(tcpClient, destination.Address.ToString(), destination.Port, cancellationToken);
    }

    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            var stream = tcpClient.GetStream();
            var isIp = IPAddress.TryParse(host, out var ipAddress);
            if (isIp && ipAddress!.AddressFamily == AddressFamily.InterNetworkV6)
                throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");
            if (!isIp)
                ipAddress = IPAddress.Parse("0.0.0.1"); // SOCKS4a marker; host is sent separately

            var request = BuildRequest(ipAddress!, port, isIp ? null : host, options.UserName);
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var reply = new byte[8];
            await stream.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
            if (reply[0] != 0)
                throw new ProxyClientException(SocketError.ProtocolNotSupported, $"Invalid SOCKS4 reply version: {reply[0]}");

            var code = (Socks4ReplyCode)reply[1];
            if (code != Socks4ReplyCode.RequestGranted)
                ThrowSocks4Error(code);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    public async Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        try {
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    private static ReadOnlyMemory<byte> BuildRequest(IPAddress ip, int port, string? domainName, string? userId)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            throw new ProxyClientException(SocketError.AddressFamilyNotSupported, "SOCKS4 only supports IPv4 addresses.");

        var user = userId ?? string.Empty;
        var userBytes = Encoding.UTF8.GetBytes(user);
        var hostBytes = domainName != null ? Encoding.UTF8.GetBytes(domainName) : null;
        var addressBytes = ip.GetAddressBytes();
        var buffer = new byte[1 + 1 + 2 + 4 + userBytes.Length + 1 + (hostBytes?.Length ?? 0) + (domainName != null ? 1 : 0)];
        var o = 0;
        buffer[o++] = 0x04; // VN
        buffer[o++] = 0x01; // CD=CONNECT
        buffer[o++] = (byte)(port >> 8);
        buffer[o++] = (byte)(port & 0xFF);
        Array.Copy(addressBytes, 0, buffer, o, 4); o += 4;
        if (userBytes.Length > 0) Array.Copy(userBytes, 0, buffer, o, userBytes.Length);
        o += userBytes.Length;
        buffer[o++] = 0x00; // user id null terminator
        if (hostBytes != null) {
            Array.Copy(hostBytes, 0, buffer, o, hostBytes.Length);
            o += hostBytes.Length;
            buffer[o++] = 0x00; // host null terminator (SOCKS4a)
        }
        return new ReadOnlyMemory<byte>(buffer, 0, o);
    }

    private static void ThrowSocks4Error(Socks4ReplyCode code)
    {
        throw new ProxyClientException(code switch {
            Socks4ReplyCode.RequestRejectedOrFailed => SocketError.AccessDenied,
            Socks4ReplyCode.CannotConnectToIdentd => SocketError.ConnectionRefused,
            Socks4ReplyCode.DifferingUserId => SocketError.AccessDenied,
            _ => SocketError.SocketError
        });
    }
}
