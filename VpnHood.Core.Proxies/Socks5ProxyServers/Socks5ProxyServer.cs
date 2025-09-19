using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Proxies.Socks5Proxy;
using System.Buffers;

namespace VpnHood.Core.Proxies.Socks5ProxyServers;

public sealed class Socks5ProxyServer(
    Socks5ProxyServerOptions options,
    ILogger<Socks5ProxyServer>? logger = null)
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, logger)
{
    protected override async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var clientEndpoint = client.Client.RemoteEndPoint as IPEndPoint ?? new IPEndPoint(IPAddress.None, 0);
        Logger.LogDebug("Handling SOCKS5 client connection from {ClientEndpoint}", clientEndpoint);

        try
        {
            using var clientToDispose = client; // ensure disposal on all paths
            client.NoDelay = true;
            var networkStream = client.GetStream();

            // Perform handshake
            var handshakeResult = await PerformHandshakeAsync(networkStream, clientEndpoint, cancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
                return;

            Logger.LogDebug("Processing {Command} command from {ClientEndpoint}", handshakeResult.RequestHeader.Command, clientEndpoint);

            // Handle request based on command
            switch (handshakeResult.RequestHeader.Command)
            {
                case Socks5Command.Connect:
                    {
                        var destination = await ReadDestinationAsync(networkStream, handshakeResult.RequestHeader.AddressType, cancellationToken).ConfigureAwait(false);
                        await HandleConnectCommandAsync(networkStream, destination.Address, destination.Port, cancellationToken, clientEndpoint).ConfigureAwait(false);
                        break;
                    }
                case Socks5Command.UdpAssociate:
                    {
                        var udpResult = await HandleUdpAssociateCommandAsync(networkStream, client,
                            handshakeResult.RequestHeader.AddressType, clientEndpoint, cancellationToken).ConfigureAwait(false);

                        await SendReplyAsync(networkStream, Socks5CommandReply.Succeeded, udpResult.BindAddress,
                            udpResult.BindPort, cancellationToken).ConfigureAwait(false);

                        // Keep the TCP connection open until the client closes it
                        var buffer = new byte[1];
                        try
                        {
                            _ = await networkStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Logger.LogDebug(ex, "TCP connection closed for UDP associate with {ClientEndpoint}", clientEndpoint);
                        }
                        break;
                    }
                default:
                    {
                        Logger.LogWarning("Unsupported command {Command} from {ClientEndpoint}", handshakeResult.RequestHeader.Command, clientEndpoint);
                        await SendReplyAsync(networkStream, Socks5CommandReply.CommandNotSupported, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
                        break;
                    }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling SOCKS5 client {ClientEndpoint}", clientEndpoint);
        }
    }

    private async Task<Socks5HandshakeResult> PerformHandshakeAsync(NetworkStream networkStream,
        IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(options.HandshakeTimeout);

            // Authentication negotiation
            var authType = await NegotiateAuthAsync(networkStream, requireAuth: options.Username != null, handshakeCts.Token).ConfigureAwait(false);
            if (authType == Socks5AuthenticationType.UsernamePassword)
            {
                var authResult = await HandleUserPassAuthAsync(networkStream, options.Username!,
                    options.Password ?? string.Empty, handshakeCts.Token).ConfigureAwait(false);

                Logger.LogDebug("Authentication result for {ClientEndpoint}", clientEndpoint);
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
            Logger.LogDebug("Handshake cancelled for {ClientEndpoint}", clientEndpoint);
            return Socks5HandshakeResult.Invalid;
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error during handshake for {ClientEndpoint}", clientEndpoint);
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
                throw new UnauthorizedAccessException("No acceptable authentication methods found");
            }
        }

        // Send selected method
        await stream.WriteAsync(new byte[] { 5, (byte)selectedAuthType }, cancellationToken).ConfigureAwait(false);

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
        IPEndPoint clientEndpoint)
    {
        try
        {
            Logger.LogDebug("Connecting to {DestAddress}:{DestPort} for {ClientEndpoint}", destinationAddress, destinationPort, clientEndpoint);

            using var remoteClient = new TcpClient(destinationAddress.AddressFamily);
            remoteClient.NoDelay = true;

            // Set connection timeout
            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(destinationAddress, destinationPort, connectionCts.Token).ConfigureAwait(false);
            }

            var localEndPoint = (IPEndPoint)remoteClient.Client.LocalEndPoint!;
            await SendReplyAsync(clientStream, Socks5CommandReply.Succeeded, localEndPoint.Address, localEndPoint.Port, cancellationToken).ConfigureAwait(false);

            Logger.LogDebug("Tunneling established between {ClientEndpoint} and {DestAddress}:{DestPort}", clientEndpoint, destinationAddress, destinationPort);

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
            Logger.LogError(exception, "Failed to establish connection to {DestAddress}:{DestPort} for {ClientEndpoint}", destinationAddress, destinationPort, clientEndpoint);
            await SendReplyAsync(clientStream, Socks5CommandReply.GeneralSocksServerFailure, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<UdpAssociateResult> HandleUdpAssociateCommandAsync(NetworkStream stream, TcpClient controlTcpClient,
        Socks5AddressType addressType, IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        // Read the client's UDP endpoint (maybe ignored) because client may be behind NAT
        _ = await ReadDestinationAsync(stream, addressType, cancellationToken).ConfigureAwait(false);

        // Create UDP socket for communicating with the SOCKS5 client
        var proxyUdpClient = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
        var localEndPoint = (IPEndPoint)proxyUdpClient.Client.LocalEndPoint!;

        var relayCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Start UDP relay and TCP monitor tasks
        _ = UdpRelayLoopAsync(proxyUdpClient, clientEndpoint, relayCts.Token);
        _ = MonitorTcpConnectionAsync(controlTcpClient, relayCts, proxyUdpClient);

        Logger.LogDebug("UDP associate established for {ClientEndpoint} on port {Port}", clientEndpoint, localEndPoint.Port);

        return new UdpAssociateResult { BindAddress = IPAddress.Any, BindPort = localEndPoint.Port };
    }

    private async Task MonitorTcpConnectionAsync(TcpClient tcpClient, CancellationTokenSource cts, UdpClient udpClient)
    {
        try
        {
            var buffer = new byte[1];
            _ = await tcpClient.GetStream().ReadAsync(buffer, cts.Token).ConfigureAwait(false);
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
                Logger.LogError(exception, "Error during UDP associate cleanup");
            }
            finally
            {
                cts.Dispose();
            }
        }
    }

    private async Task UdpRelayLoopAsync(UdpClient proxyUdpClient, IPEndPoint clientEndpoint, CancellationToken cancellationToken)
    {
        IPEndPoint? clientUdpEndpoint = null;

        try
        {
            Logger.LogDebug("Starting UDP relay loop for {ClientEndpoint}", clientEndpoint);

            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await proxyUdpClient.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                var sourceEndpoint = result.RemoteEndPoint;
                var data = result.Buffer;

                if (clientUdpEndpoint == null || sourceEndpoint.Equals(clientUdpEndpoint))
                {
                    // First packet or packet from client -> parse and forward to destination
                    clientUdpEndpoint ??= sourceEndpoint;
                    await HandleUdpClientToDestinationAsync(proxyUdpClient, data, clientUdpEndpoint, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    // Packet from destination -> wrap and send back to client
                    await HandleUdpDestinationToClientAsync(proxyUdpClient, data, sourceEndpoint, clientUdpEndpoint, clientUdpEndpoint, cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("UDP relay loop cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error in UDP relay loop for {ClientEndpoint}", clientEndpoint);
        }
    }

    private async Task HandleUdpClientToDestinationAsync(UdpClient proxyUdpClient, byte[] data,
        IPEndPoint clientUdpEndpoint, CancellationToken cancellationToken)
    {
        if (data.Length < 7 || data[0] != 0 || data[1] != 0 || data[2] != 0)
        {
            Logger.LogWarning("Invalid SOCKS5 UDP packet format from {ClientEndpoint}", clientUdpEndpoint);
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
                    Logger.LogWarning("Unsupported address type {AddressType} from {ClientEndpoint}", addressType, clientUdpEndpoint);
                    return;
            }

            var destinationPort = data[offset] << 8 | data[offset + 1];
            offset += 2;

            // Avoid extra allocation/copy by sending a slice of the original buffer
            _ = await proxyUdpClient.SendAsync(data.AsMemory(offset), new IPEndPoint(destinationAddress, destinationPort), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogWarning(exception, "Failed to relay UDP packet from client {ClientEndpoint}", clientUdpEndpoint);
        }
    }

    // Pseudocode:
    // - Compute address bytes, header length, total length
    // - Rent Memory<byte> from MemoryPool for total length
    // - Fill SOCKS5 UDP header into span
    // - Copy payload into span after header
    // - Send ReadOnlyMemory<byte> via UdpClient.SendAsync
    // - Dispose memory owner via using to return buffer to pool
    private async Task HandleUdpDestinationToClientAsync(
        UdpClient proxyUdpClient,
        byte[] data,
        IPEndPoint sourceEndpoint,
        IPEndPoint clientEndpoint,
        IPEndPoint clientUdpEndpoint,
        CancellationToken cancellationToken)
    {
        try
        {
            var addressBytes = sourceEndpoint.Address.GetAddressBytes();
            var headerLength = 3 + 1 + addressBytes.Length + 2;
            var totalLength = headerLength + data.Length;

            using var owner = MemoryPool<byte>.Shared.Rent(totalLength);
            var mem = owner.Memory[..totalLength];
            var span = mem.Span;

            // RSV + FRAG
            span[0] = 0;
            span[1] = 0;
            span[2] = 0;

            // Address type
            span[3] = (byte)(sourceEndpoint.Address.AddressFamily == AddressFamily.InterNetworkV6
                ? Socks5AddressType.IpV6
                : Socks5AddressType.IpV4);

            var offset = 4;
            addressBytes.CopyTo(span[offset..]);
            offset += addressBytes.Length;

            // Port
            span[offset++] = (byte)(sourceEndpoint.Port >> 8);
            span[offset] = (byte)(sourceEndpoint.Port & 0xFF);

            // Payload
            data.AsSpan().CopyTo(span[headerLength..]);

            await proxyUdpClient.SendAsync(mem, clientEndpoint, cancellationToken).ConfigureAwait(false);

            Logger.LogDebug(
                "Relayed UDP response from {Source} to {ClientEndpoint}, payload size: {Size}, response size: {ResponseSize}",
                sourceEndpoint, clientUdpEndpoint, data.Length, totalLength);
        }
        catch (Exception exception)
        {
            Logger.LogWarning(exception,
                "Failed to relay UDP response from {Source} to client {ClientEndpoint}",
                sourceEndpoint, clientUdpEndpoint);
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
                // NetworkStream.FlushAsync is a no-op; avoid extra calls to reduce overhead
            }
        }
        catch when (cancellationToken.IsCancellationRequested)
        {
            // Expected during cancellation
        }
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

                    byte[]? rented = null;
                    try
                    {
                        rented = ArrayPool<byte>.Shared.Rent(length + 2);
                        var mem = rented.AsMemory(0, length + 2);
                        await stream.ReadExactlyAsync(mem, cancellationToken).ConfigureAwait(false);
                        var span = mem.Span;
                        var port = span[length] << 8 | span[length + 1];
                        var hostname = Encoding.UTF8.GetString(span[..length]);
                        var ipAddresses = await Dns.GetHostAddressesAsync(hostname, cancellationToken).ConfigureAwait(false);
                        var ipAddress = ipAddresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork) ?? ipAddresses[0];
                        return new IPEndPoint(ipAddress, port);
                    }
                    finally
                    {
                        if (rented is not null)
                            ArrayPool<byte>.Shared.Return(rented);
                    }
                }
            default:
                throw new NotSupportedException($"Unsupported address type: {addressType}");
        }
    }

    private static async Task SendReplyAsync(NetworkStream stream, Socks5CommandReply reply, IPAddress bindAddress, int bindPort, CancellationToken cancellationToken)
    {
        var addressBytes = bindAddress.GetAddressBytes();
        var addressType = bindAddress.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4;
        var length = 4 + addressBytes.Length + 2;
        byte[]? response = null;
        try
        {
            response = ArrayPool<byte>.Shared.Rent(length);
            response[0] = 5; response[1] = (byte)reply; response[2] = 0; response[3] = (byte)addressType;
            addressBytes.CopyTo(response, 4);
            response[4 + addressBytes.Length] = (byte)(bindPort >> 8);
            response[4 + addressBytes.Length + 1] = (byte)(bindPort & 0xFF);
            await stream.WriteAsync(response.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (response is not null)
                ArrayPool<byte>.Shared.Return(response);
        }
    }

}
