using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Proxies.Socks5Proxy;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public sealed class Socks5ProxyServer : IDisposable
{
    private readonly Socks5ProxyServerOptions _options;
    private readonly ILogger<Socks5ProxyServer>? _logger;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _serverCts = new();
    private volatile bool _isRunning;

    public Socks5ProxyServer(Socks5ProxyServerOptions options, ILogger<Socks5ProxyServer>? logger = null)
    {
        _options = options;
        _logger = logger;
        _listener = new TcpListener(_options.ListenEndPoint);
    }

    public void Start()
    {
        if (_isRunning) return;
        _listener.Start(_options.Backlog);
        _isRunning = true;
        _logger?.LogInformation("SOCKS5 proxy server started on {EndPoint}", _options.ListenEndPoint);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _serverCts.Cancel();
        _listener.Stop();
        _logger?.LogInformation("SOCKS5 proxy server stopped");
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _serverCts.Token);

        Start();
        try
        {
            while (!linkedCts.Token.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(linkedCts.Token).ConfigureAwait(false);
                    _ = HandleClientAsync(client, linkedCts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception exception)
                {
                    _logger?.LogError(exception, "Error accepting client connection");
                }
            }
        }
        finally
        {
            Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var clientEndpointAddress = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _logger?.LogDebug("Handling SOCKS5 client connection from {ClientEndpoint}", clientEndpointAddress);

        try
        {
            client.NoDelay = true;
            var networkStream = client.GetStream();

            // Perform handshake
            var handshakeResult = await PerformHandshakeAsync(networkStream, clientEndpointAddress, cancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
                return;

            _logger?.LogDebug("Processing {Command} command from {ClientEndpoint}", handshakeResult.RequestHeader.Command, clientEndpointAddress);

            // Handle request based on command
            switch (handshakeResult.RequestHeader.Command)
            {
                case Socks5Command.Connect:
                    {
                        var destination = await ReadDestinationAsync(networkStream, handshakeResult.RequestHeader.AddressType, cancellationToken).ConfigureAwait(false);
                        await HandleConnectCommandAsync(networkStream, destination.Address, destination.Port, cancellationToken, clientEndpointAddress).ConfigureAwait(false);
                        break;
                    }
                case Socks5Command.UdpAssociate:
                    {
                        var udpResult = await HandleUdpAssociateCommandAsync(networkStream, client, handshakeResult.RequestHeader.AddressType, cancellationToken, clientEndpointAddress).ConfigureAwait(false);
                        await SendReplyAsync(networkStream, Socks5CommandReply.Succeeded, udpResult.BindAddress, udpResult.BindPort, cancellationToken).ConfigureAwait(false);

                        // Keep the TCP connection open until the client closes it
                        var buffer = new byte[1];
                        try
                        {
                            _ = await networkStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogDebug(ex, "TCP connection closed for UDP associate with {ClientEndpoint}", clientEndpointAddress);
                        }
                        break;
                    }
                default:
                    {
                        _logger?.LogWarning("Unsupported command {Command} from {ClientEndpoint}", handshakeResult.RequestHeader.Command, clientEndpointAddress);
                        await SendReplyAsync(networkStream, Socks5CommandReply.CommandNotSupported, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
                        break;
                    }
            }
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Error handling SOCKS5 client {ClientEndpoint}", clientEndpointAddress);
        }
    }

    private async Task<Socks5HandshakeResult> PerformHandshakeAsync(NetworkStream networkStream,
        string clientEndpointAddress, CancellationToken cancellationToken)
    {
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(_options.HandshakeTimeout);

            // Authentication negotiation
            var authType = await NegotiateAuthAsync(networkStream, requireAuth: _options.Username != null, handshakeCts.Token).ConfigureAwait(false);
            if (authType == Socks5AuthenticationType.UsernamePassword)
            {
                var authResult = await HandleUserPassAuthAsync(networkStream, _options.Username!,
                    _options.Password ?? string.Empty, handshakeCts.Token).ConfigureAwait(false);

                _logger?.LogDebug("Authentication result for {ClientEndpoint}", clientEndpointAddress);
                if (!authResult)
                    return Socks5HandshakeResult.Invalid;
            }

            // Read request header
            // ReSharper disable once PossiblyMistakenUseOfCancellationToken
            var requestHeader = await ReadRequestHeaderAsync(networkStream, cancellationToken).ConfigureAwait(false);
            return Socks5HandshakeResult.Valid(authType, requestHeader);
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("Handshake cancelled for {ClientEndpoint}", clientEndpointAddress);
            return Socks5HandshakeResult.Invalid;
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Error during handshake for {ClientEndpoint}", clientEndpointAddress);
            return Socks5HandshakeResult.Invalid;
        }
    }

    private async Task<Socks5AuthenticationType> NegotiateAuthAsync(NetworkStream stream, bool requireAuth, CancellationToken cancellationToken)
    {
        // Read version and number of methods
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        if (header[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version: {header[0]}");
        }

        var numberOfMethods = header[1];
        if (numberOfMethods == 0)
        {
            throw new ProtocolViolationException("No authentication methods provided");
        }

        // Read supported methods
        var methods = new byte[numberOfMethods];
        await stream.ReadExactlyAsync(methods, cancellationToken).ConfigureAwait(false);

        var supportsUserPass = methods.Contains((byte)Socks5AuthenticationType.UsernamePassword);
        var supportsNoAuth = methods.Contains((byte)Socks5AuthenticationType.NoAuthenticationRequired);

        Socks5AuthenticationType selectedAuthType;

        if (requireAuth)
        {
            if (!supportsUserPass)
            {
                // Send "no acceptable methods" response
                await stream.WriteAsync(new byte[] { 5, (byte)Socks5AuthenticationType.ReplyNoAcceptableMethods }, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                throw new UnauthorizedAccessException("Client does not support required authentication method");
            }
            selectedAuthType = Socks5AuthenticationType.UsernamePassword;
        }
        else
        {
            // Prefer no auth if available, otherwise username/password
            selectedAuthType = supportsNoAuth ? Socks5AuthenticationType.NoAuthenticationRequired :
                      supportsUserPass ? Socks5AuthenticationType.UsernamePassword :
                      Socks5AuthenticationType.ReplyNoAcceptableMethods;

            if (selectedAuthType == Socks5AuthenticationType.ReplyNoAcceptableMethods)
            {
                await stream.WriteAsync(new byte[] { 5, (byte)selectedAuthType }, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                throw new UnauthorizedAccessException("No acceptable authentication methods found");
            }
        }

        // Send selected method
        await stream.WriteAsync(new byte[] { 5, (byte)selectedAuthType }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        return selectedAuthType;
    }

    private static async Task<bool> HandleUserPassAuthAsync(NetworkStream stream, string expectedUsername, string expectedPassword, CancellationToken cancellationToken)
    {
        // Read version
        var version = new byte[1];
        await stream.ReadExactlyAsync(version, cancellationToken).ConfigureAwait(false);

        if (version[0] != 1)
        {
            await stream.WriteAsync(new byte[] { 1, 0xFF }, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }

        // Read username length
        var usernameLengthBuffer = new byte[1];
        await stream.ReadExactlyAsync(usernameLengthBuffer, cancellationToken).ConfigureAwait(false);
        var usernameLength = usernameLengthBuffer[0];

        // Read username
        var usernameBytes = new byte[usernameLength];
        await stream.ReadExactlyAsync(usernameBytes, cancellationToken).ConfigureAwait(false);

        // Read password length
        var passwordLengthBuffer = new byte[1];
        await stream.ReadExactlyAsync(passwordLengthBuffer, cancellationToken).ConfigureAwait(false);
        var passwordLength = passwordLengthBuffer[0];

        // Read password
        var passwordBytes = new byte[passwordLength];
        await stream.ReadExactlyAsync(passwordBytes, cancellationToken).ConfigureAwait(false);

        // Validate credentials
        var username = Encoding.UTF8.GetString(usernameBytes);
        var password = Encoding.UTF8.GetString(passwordBytes);

        var isValid = string.Equals(username, expectedUsername, StringComparison.Ordinal) &&
                     string.Equals(password, expectedPassword, StringComparison.Ordinal);

        // Send response
        await stream.WriteAsync(new byte[] { 1, (byte)(isValid ? 0 : 0xFF) }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        return isValid;
    }

    private static async Task<RequestHeader> ReadRequestHeaderAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var requestHeaderBytes = new byte[4];
        await stream.ReadExactlyAsync(requestHeaderBytes, cancellationToken).ConfigureAwait(false);

        if (requestHeaderBytes[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version in request: {requestHeaderBytes[0]}");
        }

        return new RequestHeader
        {
            Command = (Socks5Command)requestHeaderBytes[1],
            AddressType = (Socks5AddressType)requestHeaderBytes[3]
        };
    }

    private async Task HandleConnectCommandAsync(NetworkStream clientStream, IPAddress destinationAddress, int destinationPort, CancellationToken cancellationToken,
        string clientEndpointAddress)
    {
        try
        {
            _logger?.LogDebug("Connecting to {DestAddress}:{DestPort} for {ClientEndpoint}", destinationAddress, destinationPort, clientEndpointAddress);

            using var remoteClient = new TcpClient(destinationAddress.AddressFamily);
            remoteClient.NoDelay = true;

            // Set connection timeout
            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(_options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(destinationAddress, destinationPort, connectionCts.Token).ConfigureAwait(false);
            }

            var localEndPoint = (IPEndPoint)remoteClient.Client.LocalEndPoint!;
            await SendReplyAsync(clientStream, Socks5CommandReply.Succeeded, localEndPoint.Address, localEndPoint.Port, cancellationToken).ConfigureAwait(false);

            _logger?.LogDebug("Tunneling established between {ClientEndpoint} and {DestAddress}:{DestPort}", clientEndpointAddress, destinationAddress, destinationPort);

            var remoteStream = remoteClient.GetStream();
            await PumpStreamsAsync(clientStream, remoteStream, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.TtlExpired, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.ConnectionRefused)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.ConnectionRefused, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.HostUnreachable)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.HostUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException exception) when (exception.SocketErrorCode == SocketError.NetworkUnreachable)
        {
            await SendReplyAsync(clientStream, Socks5CommandReply.NetworkUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Failed to establish connection to {DestAddress}:{DestPort} for {ClientEndpoint}", destinationAddress, destinationPort, clientEndpointAddress);
            await SendReplyAsync(clientStream, Socks5CommandReply.GeneralSocksServerFailure, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<UdpAssociateResult> HandleUdpAssociateCommandAsync(NetworkStream stream, TcpClient controlTcpClient, Socks5AddressType addressType, CancellationToken cancellationToken, string clientEndpointAddress)
    {
        // Read the client's UDP endpoint (may be ignored)
        _ = await ReadDestinationAsync(stream, addressType, cancellationToken).ConfigureAwait(false);

        // Create UDP socket for communicating with the SOCKS5 client
        var proxyUdpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        var localEndPoint = (IPEndPoint)proxyUdpClient.Client.LocalEndPoint!;

        var relayCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Start UDP relay and TCP monitor tasks
        _ = Task.Run(() => UdpRelayLoopAsync(proxyUdpClient, clientEndpointAddress, relayCts.Token), relayCts.Token);
        _ = Task.Run(() => MonitorTcpConnectionAsync(controlTcpClient, relayCts, proxyUdpClient), relayCts.Token);

        _logger?.LogDebug("UDP associate established for {ClientEndpoint} on port {Port}", clientEndpointAddress, localEndPoint.Port);

        return new UdpAssociateResult { BindAddress = IPAddress.Any, BindPort = localEndPoint.Port };
    }

    private async Task MonitorTcpConnectionAsync(TcpClient tcpClient, CancellationTokenSource cts, UdpClient udpClient)
    {
        try
        {
            var buffer = new byte[1];
            await tcpClient.GetStream().ReadAsync(buffer, cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // TCP connection closed or error occurred
        }
        finally
        {
            try
            {
                udpClient.Dispose();
                await cts.CancelAsync();
            }
            catch (Exception exception)
            {
                _logger?.LogError(exception, "Error during UDP associate cleanup");
            }
        }
    }

    private async Task UdpRelayLoopAsync(UdpClient proxyUdpClient, string clientEndpointAddress, CancellationToken cancellationToken)
    {
        IPEndPoint? clientUdpEndpoint = null;

        try
        {
            _logger?.LogDebug("Starting UDP relay loop for {ClientEndpoint}", clientEndpointAddress);

            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await proxyUdpClient.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                var sourceEndpoint = result.RemoteEndPoint;
                var data = result.Buffer;

                if (clientUdpEndpoint == null || sourceEndpoint.Equals(clientUdpEndpoint))
                {
                    // First packet or packet from client -> parse and forward to destination
                    clientUdpEndpoint ??= sourceEndpoint;
                    await HandleUdpClientToDestinationAsync(proxyUdpClient, data, sourceEndpoint, clientEndpointAddress, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    // Packet from destination -> wrap and send back to client
                    await HandleUdpDestinationToClientAsync(proxyUdpClient, data, sourceEndpoint, clientUdpEndpoint, clientEndpointAddress, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("UDP relay loop cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Error in UDP relay loop for {ClientEndpoint}", clientEndpointAddress);
        }
    }

    private async Task HandleUdpClientToDestinationAsync(UdpClient proxyUdpClient, byte[] data, IPEndPoint clientEndpoint, string clientDescription, CancellationToken cancellationToken)
    {
        if (data.Length < 7 || data[0] != 0 || data[1] != 0 || data[2] != 0)
        {
            _logger?.LogWarning("Invalid SOCKS5 UDP packet format from {ClientEndpoint}", clientDescription);
            return;
        }

        try
        {
            var offset = 3;
            var addressType = (Socks5AddressType)data[offset++];

            IPAddress? destinationAddress;

            switch (addressType)
            {
                case Socks5AddressType.IpV4:
                    destinationAddress = new IPAddress(new ReadOnlySpan<byte>(data, offset, 4));
                    offset += 4;
                    break;

                case Socks5AddressType.IpV6:
                    destinationAddress = new IPAddress(new ReadOnlySpan<byte>(data, offset, 16));
                    offset += 16;
                    break;

                case Socks5AddressType.DomainName:
                    var domainLength = data[offset++];
                    var domain = Encoding.UTF8.GetString(data, offset, domainLength);
                    offset += domainLength;

                    var addresses = await Dns.GetHostAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
                    destinationAddress = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
                    break;

                default:
                    _logger?.LogWarning("Unsupported address type {AddressType} from {ClientEndpoint}", addressType, clientDescription);
                    return;
            }

            var destinationPort = data[offset] << 8 | data[offset + 1];
            offset += 2;

            var payload = new byte[data.Length - offset];
            Array.Copy(data, offset, payload, 0, payload.Length);

            await proxyUdpClient.SendAsync(payload, new IPEndPoint(destinationAddress, destinationPort)).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Failed to relay UDP packet from client {ClientEndpoint}", clientDescription);
        }
    }

    private async Task HandleUdpDestinationToClientAsync(UdpClient proxyUdpClient, byte[] data, IPEndPoint sourceEndpoint, IPEndPoint clientEndpoint, string clientDescription, CancellationToken cancellationToken)
    {
        try
        {
            // Wrap response in SOCKS5 UDP format and send back to client
            var response = BuildUdpResponse(sourceEndpoint, data);
            await proxyUdpClient.SendAsync(response, clientEndpoint).ConfigureAwait(false);

            _logger?.LogDebug("Relayed UDP response from {Source} to {ClientEndpoint}, payload size: {Size}, response size: {ResponseSize}",
                sourceEndpoint, clientDescription, data.Length, response.Length);
        }
        catch (Exception exception)
        {
            _logger?.LogWarning(exception, "Failed to relay UDP response from {Source} to client {ClientEndpoint}", sourceEndpoint, clientDescription);
        }
    }

    private static async Task PumpStreamsAsync(NetworkStream clientStream, NetworkStream remoteStream, CancellationToken cancellationToken)
    {
        const int bufferSize = 4096;
        var tasks = new[]
        {
            CopyStreamAsync(clientStream, remoteStream, bufferSize, cancellationToken),
            CopyStreamAsync(remoteStream, clientStream, bufferSize, cancellationToken)
        };

        try
        {
            await Task.WhenAny(tasks).ConfigureAwait(false);
        }
        finally
        {
            // Cancel remaining operations
            await Task.WhenAll(tasks.Select(async task =>
            {
                try { await task.ConfigureAwait(false); }
                catch { /* Ignore exceptions during cleanup */ }
            })).ConfigureAwait(false);
        }
    }

    private static async Task CopyStreamAsync(Stream sourceStream, Stream destinationStream, int bufferSize, CancellationToken cancellationToken)
    {
        var buffer = new byte[bufferSize];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var bytesRead = await sourceStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                await destinationStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch when (cancellationToken.IsCancellationRequested)
        {
            // Expected during cancellation
        }
    }

    private static byte[] BuildUdpResponse(IPEndPoint sourceEndpoint, byte[] payload)
    {
        var addressBytes = sourceEndpoint.Address.GetAddressBytes();
        var header = new byte[3 + 1 + addressBytes.Length + 2];
        header[0] = 0; header[1] = 0; header[2] = 0;
        header[3] = (byte)(sourceEndpoint.Address.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4);
        var offset = 4;
        addressBytes.CopyTo(header, offset);
        offset += addressBytes.Length;
        header[offset++] = (byte)(sourceEndpoint.Port >> 8);
        header[offset] = (byte)(sourceEndpoint.Port & 0xFF);
        var response = new byte[header.Length + payload.Length];
        Buffer.BlockCopy(header, 0, response, 0, header.Length);
        Buffer.BlockCopy(payload, 0, response, header.Length, payload.Length);
        return response;
    }

    private static async Task<IPEndPoint> ReadDestinationAsync(NetworkStream stream, Socks5AddressType addressType, CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                {
                    var buffer = new byte[6];
                    await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
                    return new IPEndPoint(new IPAddress(buffer.AsSpan(0, 4)), buffer[4] << 8 | buffer[5]);
                }
            case Socks5AddressType.IpV6:
                {
                    var buffer = new byte[18];
                    await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
                    return new IPEndPoint(new IPAddress(buffer.AsSpan(0, 16)), buffer[16] << 8 | buffer[17]);
                }
            case Socks5AddressType.DomainName:
                {
                    var lengthBuffer = new byte[1];
                    await stream.ReadExactlyAsync(lengthBuffer, cancellationToken).ConfigureAwait(false);
                    var length = lengthBuffer[0];
                    var buffer = new byte[length + 2];
                    await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
                    var port = buffer[length] << 8 | buffer[length + 1];
                    var hostname = Encoding.UTF8.GetString(buffer.AsSpan(0, length));
                    var ipAddresses = await Dns.GetHostAddressesAsync(hostname, cancellationToken).ConfigureAwait(false);
                    var ipAddress = ipAddresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork) ?? ipAddresses[0];
                    return new IPEndPoint(ipAddress, port);
                }
            default:
                throw new NotSupportedException($"Unsupported address type: {addressType}");
        }
    }

    private static async Task SendReplyAsync(NetworkStream stream, Socks5CommandReply reply, IPAddress bindAddress, int bindPort, CancellationToken cancellationToken)
    {
        var addressBytes = bindAddress.GetAddressBytes();
        var addressType = bindAddress.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4;
        var response = new byte[4 + addressBytes.Length + 2];
        response[0] = 5; response[1] = (byte)reply; response[2] = 0; response[3] = (byte)addressType;
        addressBytes.CopyTo(response, 4);
        response[4 + addressBytes.Length] = (byte)(bindPort >> 8);
        response[4 + addressBytes.Length + 1] = (byte)(bindPort & 0xFF);
        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        Stop();
        _serverCts.Dispose();
    }
}
