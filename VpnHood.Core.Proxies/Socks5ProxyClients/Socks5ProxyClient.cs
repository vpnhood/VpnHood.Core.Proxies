using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Proxies.Socks5Proxy;

namespace VpnHood.Core.Proxies.Socks5ProxyClients;

public class Socks5ProxyClient(Socks5ProxyClientOptions options, ILogger<Socks5ProxyClient>? logger = null)
    : IProxyClient
{
    private readonly Socks5ProxyClientOptions _options = options ?? throw new ArgumentNullException(nameof(options));
    private bool _isAuthenticated;

    public IPEndPoint ProxyEndPoint => _options.ProxyEndPoint;

    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);

        try {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            var ipAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
            await ConnectAsync(tcpClient, new IPEndPoint(ipAddress, port), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to resolve or connect to {Host}:{Port}", host, port);
            throw;
        }
    }

    public async Task<TimeSpan> CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        try {
            var startTime = Environment.TickCount64;
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            var stream = tcpClient.GetStream();
            await EnsureAuthenticatedAsync(stream, cancellationToken).ConfigureAwait(false);
            return TimeSpan.FromMilliseconds(Environment.TickCount64 - startTime);
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    public async Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentNullException.ThrowIfNull(destination);

        logger?.LogDebug("Connecting to {Destination} through SOCKS5 proxy {ProxyEndPoint}", destination, ProxyEndPoint);

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            var stream = tcpClient.GetStream();
            await EnsureAuthenticatedAsync(stream, cancellationToken).ConfigureAwait(false);
            await PerformConnectAsync(stream, destination, cancellationToken).ConfigureAwait(false);
            
            logger?.LogDebug("SOCKS5 CONNECT tunnel established to {Destination}", destination);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to connect to {Destination} through SOCKS5 proxy", destination);
            tcpClient.Close();
            throw;
        }
    }

    public async Task<IPEndPoint> CreateUdpAssociateAsync(TcpClient tcpClient, CancellationToken cancellationToken) =>
        await CreateUdpAssociateAsync(tcpClient, null, cancellationToken).ConfigureAwait(false);

    public async Task<IPEndPoint> CreateUdpAssociateAsync(TcpClient tcpClient, IPEndPoint? clientUdpEndPoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);

        logger?.LogDebug("Creating UDP associate through SOCKS5 proxy");

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            var stream = tcpClient.GetStream();
            await EnsureAuthenticatedAsync(stream, cancellationToken).ConfigureAwait(false);

            var endpointToSend = clientUdpEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
            var result = await SendCommandAndReadReplyAsync(stream, Socks5Command.UdpAssociate, endpointToSend, cancellationToken).ConfigureAwait(false);

            var boundAddress = result.BoundEndpoint.Address;
            if (boundAddress == null)
            {
                throw new NotSupportedException("Proxy returned an unsupported address type for UDP ASSOCIATE");
            }

            // RFC 1928: if BND.ADDRESS is 0.0.0.0 (or ::), use the proxy's address for sending datagrams
            var resultAddress = boundAddress.Equals(IPAddress.Any) || boundAddress.Equals(IPAddress.IPv6Any)
                ? ProxyEndPoint.Address
                : boundAddress;

            var udpEndpoint = new IPEndPoint(resultAddress, result.BoundEndpoint.Port);
            logger?.LogDebug("UDP associate established on {UdpEndpoint}", udpEndpoint);
            
            return udpEndpoint;
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to create UDP associate through SOCKS5 proxy");
            throw;
        }
    }

    private async Task EnsureAuthenticatedAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        if (_isAuthenticated) return;

        await PerformAuthenticationAsync(stream, cancellationToken).ConfigureAwait(false);
        _isAuthenticated = true;
    }

    private async Task PerformAuthenticationAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        logger?.LogDebug("Performing SOCKS5 authentication negotiation");

        // Send authentication methods
        var hasCredentials = !string.IsNullOrEmpty(_options.Username);
        var methods = hasCredentials 
            ? new byte[] { 5, 2, (byte)Socks5AuthenticationType.NoAuthenticationRequired, (byte)Socks5AuthenticationType.UsernamePassword }
            : new byte[] { 5, 1, (byte)Socks5AuthenticationType.NoAuthenticationRequired };

        await stream.WriteAsync(methods, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read server response
        var response = new byte[2];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);

        if (response[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version in response: {response[0]}");
        }

        var selectedMethod = (Socks5AuthenticationType)response[1];
        logger?.LogDebug("Server selected authentication method: {Method}", selectedMethod);

        switch (selectedMethod)
        {
            case Socks5AuthenticationType.NoAuthenticationRequired:
                logger?.LogDebug("No authentication required");
                break;

            case Socks5AuthenticationType.UsernamePassword:
                if (string.IsNullOrEmpty(_options.Username))
                {
                    throw new UnauthorizedAccessException("Server requires username/password authentication but no credentials provided");
                }
                await PerformUsernamePasswordAuthAsync(stream, _options.Username, _options.Password ?? string.Empty, cancellationToken).ConfigureAwait(false);
                break;

            case Socks5AuthenticationType.ReplyNoAcceptableMethods:
                throw new UnauthorizedAccessException("No acceptable authentication methods found");

            default:
                throw new NotSupportedException($"Authentication method {selectedMethod} is not supported");
        }
    }

    private async Task PerformUsernamePasswordAuthAsync(NetworkStream stream, string username, string password, CancellationToken cancellationToken)
    {
        logger?.LogDebug("Performing username/password authentication for user: {Username}", username);

        var authBuffer = ConstructAuthBuffer(username, password);
        await stream.WriteAsync(authBuffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = new byte[2];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);

        if (response[0] != 1)
        {
            throw new ProtocolViolationException($"Invalid username/password auth version: {response[0]}");
        }

        if (response[1] != 0)
        {
            throw new UnauthorizedAccessException("Username/password authentication failed");
        }

        logger?.LogDebug("Username/password authentication successful");
    }

    private static async Task PerformConnectAsync(NetworkStream stream, IPEndPoint destination, CancellationToken cancellationToken)
    {
        var result = await SendCommandAndReadReplyAsync(stream, Socks5Command.Connect, destination, cancellationToken).ConfigureAwait(false);
        
        if (result.Reply != Socks5CommandReply.Succeeded)
        {
            throw MapSocksErrorToException(result.Reply);
        }
    }

    private static async Task<Socks5CommandResult> SendCommandAndReadReplyAsync(NetworkStream stream, Socks5Command command, IPEndPoint destination, CancellationToken cancellationToken)
    {
        // Build and send request
        var addressType = GetAddressType(destination.AddressFamily);
        var addressBytes = destination.Address.GetAddressBytes();
        var portBytes = BitConverter.GetBytes((ushort)destination.Port);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(portBytes);
        }

        var request = new byte[4 + addressBytes.Length + 2];
        request[0] = 5; // Version
        request[1] = (byte)command;
        request[2] = 0; // Reserved
        request[3] = addressType;
        
        addressBytes.CopyTo(request, 4);
        portBytes.CopyTo(request, 4 + addressBytes.Length);

        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // Read response header
        var responseHeader = new byte[4];
        await stream.ReadExactlyAsync(responseHeader, cancellationToken).ConfigureAwait(false);

        if (responseHeader[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version in reply: {responseHeader[0]}");
        }

        var reply = (Socks5CommandReply)responseHeader[1];
        var replyAddressType = (Socks5AddressType)responseHeader[3];

        // Read bound address and port
        var boundEndpoint = await ReadAddressPortAsync(stream, replyAddressType, cancellationToken).ConfigureAwait(false);
        
        return new Socks5CommandResult(command, reply, boundEndpoint);
    }

    private static async Task<Socks5Endpoint> ReadAddressPortAsync(NetworkStream stream, Socks5AddressType addressType, CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                var ipv4Buffer = new byte[6]; // 4 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv4Buffer, cancellationToken).ConfigureAwait(false);
                var ipv4Address = new IPAddress(ipv4Buffer.AsSpan(0, 4));
                var ipv4Port = ipv4Buffer[4] << 8 | ipv4Buffer[5];
                return new Socks5Endpoint(null, ipv4Address, ipv4Port);

            case Socks5AddressType.IpV6:
                var ipv6Buffer = new byte[18]; // 16 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv6Buffer, cancellationToken).ConfigureAwait(false);
                var ipv6Address = new IPAddress(ipv6Buffer.AsSpan(0, 16));
                var ipv6Port = ipv6Buffer[16] << 8 | ipv6Buffer[17];
                return new Socks5Endpoint(null, ipv6Address, ipv6Port);

            case Socks5AddressType.DomainName:
                var lengthBuffer = new byte[1];
                await stream.ReadExactlyAsync(lengthBuffer, cancellationToken).ConfigureAwait(false);
                var domainLength = lengthBuffer[0];
                
                var domainBuffer = new byte[domainLength + 2];
                await stream.ReadExactlyAsync(domainBuffer, cancellationToken).ConfigureAwait(false);
                
                var domain = Encoding.UTF8.GetString(domainBuffer.AsSpan(0, domainLength));
                var domainPort = domainBuffer[domainLength] << 8 | domainBuffer[domainLength + 1];
                
                return new Socks5Endpoint(domain, null, domainPort);

            default:
                throw new NotSupportedException($"Unsupported address type in reply: {addressType}");
        }
    }

    private static byte GetAddressType(AddressFamily addressFamily) =>
        addressFamily switch {
            AddressFamily.InterNetwork => (byte)Socks5AddressType.IpV4,
            AddressFamily.InterNetworkV6 => (byte)Socks5AddressType.IpV6,
            _ => throw new NotSupportedException($"Unsupported address family: {addressFamily}")
        };

    private static Memory<byte> ConstructAuthBuffer(string username, string password)
    {
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        
        if (usernameBytes.Length > 255)
        {
            throw new ArgumentException("Username exceeds maximum length of 255 bytes", nameof(username));
        }
        
        if (passwordBytes.Length > 255)
        {
            throw new ArgumentException("Password exceeds maximum length of 255 bytes", nameof(password));
        }

        var buffer = new byte[3 + usernameBytes.Length + passwordBytes.Length];
        buffer[0] = 1; // Version
        buffer[1] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(buffer, 2);
        buffer[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(buffer, 3 + usernameBytes.Length);
        
        return new Memory<byte>(buffer);
    }

    private static Exception MapSocksErrorToException(Socks5CommandReply reply) =>
        reply switch {
            Socks5CommandReply.GeneralSocksServerFailure => new ProxyClientException(SocketError.SocketError, "General SOCKS server failure"),
            Socks5CommandReply.ConnectionNotAllowedByRuleset => new ProxyClientException(SocketError.AccessDenied, "Connection not allowed by ruleset"),
            Socks5CommandReply.NetworkUnreachable => new ProxyClientException(SocketError.NetworkUnreachable, "Network unreachable"),
            Socks5CommandReply.HostUnreachable => new ProxyClientException(SocketError.HostUnreachable, "Host unreachable"),
            Socks5CommandReply.ConnectionRefused => new ProxyClientException(SocketError.ConnectionRefused, "Connection refused"),
            Socks5CommandReply.TtlExpired => new ProxyClientException(SocketError.TimedOut, "TTL expired"),
            Socks5CommandReply.CommandNotSupported => new ProxyClientException(SocketError.OperationNotSupported, "Command not supported"),
            Socks5CommandReply.AddressTypeNotSupported => new ProxyClientException(SocketError.AddressFamilyNotSupported, "Address type not supported"),
            _ => new ProxyClientException(SocketError.ProtocolNotSupported, $"Unknown SOCKS5 error: {reply}")
        };

    public static int WriteUdpRequest(Span<byte> destinationBuffer, IPEndPoint destination, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(destination);
        
        var addressBytes = destination.Address.GetAddressBytes();
        var addressType = GetAddressType(destination.AddressFamily);
        var requiredSize = 3 + 1 + addressBytes.Length + 2 + data.Length;
        
        if (destinationBuffer.Length < requiredSize)
        {
            throw new ArgumentException($"Destination buffer too small. Required: {requiredSize}, Available: {destinationBuffer.Length}", nameof(destinationBuffer));
        }

        var offset = 0;
        destinationBuffer[offset++] = 0; // Reserved
        destinationBuffer[offset++] = 0; // Reserved
        destinationBuffer[offset++] = 0; // Fragment
        destinationBuffer[offset++] = addressType;
        
        addressBytes.CopyTo(destinationBuffer[offset..]);
        offset += addressBytes.Length;
        
        destinationBuffer[offset++] = (byte)(destination.Port >> 8);
        destinationBuffer[offset++] = (byte)(destination.Port & 0xFF);
        
        data.CopyTo(destinationBuffer[offset..]);
        offset += data.Length;
        
        return offset;
    }

    public static Socks5Endpoint ParseUdpResponse(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> payload)
    {
        if (datagram.Length < 7)
        {
            throw new ArgumentException("Datagram too short for SOCKS5 UDP response", nameof(datagram));
        }
        
        if (datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0)
        {
            throw new NotSupportedException("Fragmented or malformed SOCKS5 UDP packet");
        }

        var addressType = (Socks5AddressType)datagram[3];
        var offset = 4;
        
        string? host = null;
        IPAddress? address = null;
        
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                address = new IPAddress(datagram.Slice(offset, 4));
                offset += 4;
                break;

            case Socks5AddressType.IpV6:
                address = new IPAddress(datagram.Slice(offset, 16));
                offset += 16;
                break;

            case Socks5AddressType.DomainName:
                var domainLength = datagram[offset++];
                host = Encoding.UTF8.GetString(datagram.Slice(offset, domainLength));
                offset += domainLength;
                break;

            default:
                throw new NotSupportedException($"Unsupported address type in UDP response: {addressType}");
        }
        
        var port = datagram[offset] << 8 | datagram[offset + 1];
        offset += 2;
        
        payload = datagram[offset..];
        return new Socks5Endpoint(host, address, port);
    }
}