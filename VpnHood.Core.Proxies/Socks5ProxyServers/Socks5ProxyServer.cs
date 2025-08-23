using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Proxies.Socks5ProxyClients;

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
        _options = options ?? throw new ArgumentNullException(nameof(options));
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
        var ct = linkedCts.Token;

        Start();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                    _ = Task.Run(() => HandleClientAsync(client, ct), ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Error accepting client connection");
                }
            }
        }
        finally
        {
            Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverCt)
    {
        var clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _logger?.LogDebug("Handling SOCKS5 client connection from {ClientEndpoint}", clientEndpoint);

        using var tcp = client;

        try
        {
            tcp.NoDelay = true;
            var stream = tcp.GetStream();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
            cts.CancelAfter(_options.HandshakeTimeout);
            var ct = cts.Token;

            // Authentication negotiation
            var authMethod = await NegotiateAuthAsync(stream, requireAuth: _options.Username != null, ct).ConfigureAwait(false);

            if (authMethod == Socks5AuthenticationType.UsernamePassword)
            {
                var authResult = await HandleUserPassAuthAsync(stream, _options.Username!, _options.Password ?? string.Empty, ct).ConfigureAwait(false);
                if (!authResult)
                {
                    _logger?.LogWarning("Authentication failed for {ClientEndpoint}", clientEndpoint);
                    return;
                }
                _logger?.LogDebug("Authentication successful for {ClientEndpoint}", clientEndpoint);
            }

            // After handshake, switch to server lifetime token for long-running connections
            var requestHeader = await ReadRequestHeaderAsync(stream, serverCt).ConfigureAwait(false);

            _logger?.LogDebug("Processing {Command} command from {ClientEndpoint}", requestHeader.Command, clientEndpoint);

            switch (requestHeader.Command)
            {
                case Socks5Command.Connect:
                    var destination = await ReadDestAsync(stream, requestHeader.AddressType, serverCt).ConfigureAwait(false);
                    await HandleConnectAsync(stream, destination.Address, destination.Port, serverCt, clientEndpoint).ConfigureAwait(false);
                    break;

                case Socks5Command.UdpAssociate:
                    var udpResult = await HandleUdpAssociateAsync(stream, tcp, requestHeader.AddressType, serverCt, clientEndpoint).ConfigureAwait(false);
                    await ReplyAsync(stream, Socks5CommandReply.Succeeded, udpResult.BindAddress, udpResult.BindPort, serverCt).ConfigureAwait(false);
                    break;

                default:
                    _logger?.LogWarning("Unsupported command {Command} from {ClientEndpoint}", requestHeader.Command, clientEndpoint);
                    await ReplyAsync(stream, Socks5CommandReply.CommandNotSupported, IPAddress.Any, 0, serverCt).ConfigureAwait(false);
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error handling SOCKS5 client {ClientEndpoint}", clientEndpoint);
        }
    }

    private async Task<Socks5AuthenticationType> NegotiateAuthAsync(NetworkStream stream, bool requireAuth, CancellationToken ct)
    {
        // Read version and number of methods
        var header = new byte[2];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);

        if (header[0] != 5)
        {
            throw new ProtocolViolationException($"Invalid SOCKS version: {header[0]}");
        }

        var numMethods = header[1];
        if (numMethods == 0)
        {
            throw new ProtocolViolationException("No authentication methods provided");
        }

        // Read supported methods
        var methods = new byte[numMethods];
        await stream.ReadExactlyAsync(methods, ct).ConfigureAwait(false);

        var supportsUserPass = methods.Contains((byte)Socks5AuthenticationType.UsernamePassword);
        var supportsNoAuth = methods.Contains((byte)Socks5AuthenticationType.NoAuthenticationRequired);

        Socks5AuthenticationType selected;

        if (requireAuth)
        {
            if (!supportsUserPass)
            {
                // Send "no acceptable methods" response
                await stream.WriteAsync(new byte[] { 5, (byte)Socks5AuthenticationType.ReplyNoAcceptableMethods }, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                throw new UnauthorizedAccessException("Client does not support required authentication method");
            }
            selected = Socks5AuthenticationType.UsernamePassword;
        }
        else
        {
            // Prefer no auth if available, otherwise username/password
            selected = supportsNoAuth ? Socks5AuthenticationType.NoAuthenticationRequired :
                      supportsUserPass ? Socks5AuthenticationType.UsernamePassword :
                      Socks5AuthenticationType.ReplyNoAcceptableMethods;

            if (selected == Socks5AuthenticationType.ReplyNoAcceptableMethods)
            {
                await stream.WriteAsync(new byte[] { 5, (byte)selected }, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                throw new UnauthorizedAccessException("No acceptable authentication methods found");
            }
        }

        // Send selected method
        await stream.WriteAsync(new byte[] { 5, (byte)selected }, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        return selected;
    }

    private static async Task<bool> HandleUserPassAuthAsync(NetworkStream stream, string expectedUser, string expectedPass, CancellationToken ct)
    {
        // Read version
        var version = new byte[1];
        await stream.ReadExactlyAsync(version, ct).ConfigureAwait(false);

        if (version[0] != 1)
        {
            await stream.WriteAsync(new byte[] { 1, 0xFF }, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            return false;
        }

        // Read username length
        var userLenBuffer = new byte[1];
        await stream.ReadExactlyAsync(userLenBuffer, ct).ConfigureAwait(false);
        var userLen = userLenBuffer[0];

        // Read username
        var userBytes = new byte[userLen];
        await stream.ReadExactlyAsync(userBytes, ct).ConfigureAwait(false);

        // Read password length
        var passLenBuffer = new byte[1];
        await stream.ReadExactlyAsync(passLenBuffer, ct).ConfigureAwait(false);
        var passLen = passLenBuffer[0];

        // Read password
        var passBytes = new byte[passLen];
        await stream.ReadExactlyAsync(passBytes, ct).ConfigureAwait(false);

        // Validate credentials
        var username = Encoding.UTF8.GetString(userBytes);
        var password = Encoding.UTF8.GetString(passBytes);

        var isValid = string.Equals(username, expectedUser, StringComparison.Ordinal) &&
                     string.Equals(password, expectedPass, StringComparison.Ordinal);

        // Send response
        await stream.WriteAsync(new byte[] { 1, (byte)(isValid ? 0 : 0xFF) }, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        return isValid;
    }

    private static async Task<RequestHeader> ReadRequestHeaderAsync(NetworkStream stream, CancellationToken ct)
    {
        var requestHeaderBytes = new byte[4];
        await stream.ReadExactlyAsync(requestHeaderBytes, ct).ConfigureAwait(false);

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

    private async Task HandleConnectAsync(NetworkStream clientStream, IPAddress destAddress, int destPort, CancellationToken cancellationToken,
        string clientEndpoint)
    {
        try
        {
            _logger?.LogDebug("Connecting to {DestAddress}:{DestPort} for {ClientEndpoint}", destAddress, destPort, clientEndpoint);

            using var remote = new TcpClient(destAddress.AddressFamily);
            remote.NoDelay = true;

            // Set connection timeout
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(TimeSpan.FromSeconds(30));

            await remote.ConnectAsync(destAddress, destPort, connectCts.Token).ConfigureAwait(false);

            var localEndPoint = (System.Net.IPEndPoint)remote.Client.LocalEndPoint!;
            await ReplyAsync(clientStream, Socks5CommandReply.Succeeded, localEndPoint.Address, localEndPoint.Port, cancellationToken).ConfigureAwait(false);

            _logger?.LogDebug("Tunneling established between {ClientEndpoint} and {DestAddress}:{DestPort}", clientEndpoint, destAddress, destPort);

            var remoteStream = remote.GetStream();
            await PumpStreamsAsync(clientStream, remoteStream, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await ReplyAsync(clientStream, Socks5CommandReply.TtlExpired, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            await ReplyAsync(clientStream, Socks5CommandReply.ConnectionRefused, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostUnreachable)
        {
            await ReplyAsync(clientStream, Socks5CommandReply.HostUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.NetworkUnreachable)
        {
            await ReplyAsync(clientStream, Socks5CommandReply.NetworkUnreachable, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to establish connection to {DestAddress}:{DestPort} for {ClientEndpoint}", destAddress, destPort, clientEndpoint);
            await ReplyAsync(clientStream, Socks5CommandReply.GeneralSocksServerFailure, IPAddress.Any, 0, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<UdpAssociateResult> HandleUdpAssociateAsync(NetworkStream stream, TcpClient controlTcp, Socks5AddressType addressType, CancellationToken ct, string clientEndpoint)
    {
        // Read the client's UDP endpoint (may be ignored)
        _ = await ReadDestAsync(stream, addressType, ct).ConfigureAwait(false);

        // Create UDP socket for communicating with the SOCKS5 client
        var proxyUdp = new UdpClient(new System.Net.IPEndPoint(IPAddress.Any, 0));
        var localEndPoint = (System.Net.IPEndPoint)proxyUdp.Client.LocalEndPoint!;

        var relayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        // Start UDP relay and TCP monitor tasks
        _ = Task.Run(() => UdpRelayLoopAsync(proxyUdp, clientEndpoint, relayCts.Token), relayCts.Token);
        _ = Task.Run(() => MonitorTcpCloseAsync(controlTcp, relayCts, proxyUdp), relayCts.Token);

        _logger?.LogDebug("UDP associate established for {ClientEndpoint} on port {Port}", clientEndpoint, localEndPoint.Port);

        return new UdpAssociateResult { BindAddress = IPAddress.Any, BindPort = localEndPoint.Port };
    }

    private async Task MonitorTcpCloseAsync(TcpClient tcp, CancellationTokenSource cts, UdpClient udp)
    {
        try
        {
            var buffer = new byte[1];
            await tcp.GetStream().ReadAsync(buffer, cts.Token).ConfigureAwait(false);
        }
        catch
        {
            // TCP connection closed or error occurred
        }
        finally
        {
            try
            {
                udp.Dispose();
                await cts.CancelAsync();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error during UDP associate cleanup");
            }
        }
    }

    private async Task UdpRelayLoopAsync(UdpClient proxyUdp, string clientEndpoint, CancellationToken ct)
    {
        System.Net.IPEndPoint? clientUdpEndpoint = null;
        var destinationSockets = new Dictionary<System.Net.IPEndPoint, UdpClient>();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var result = await proxyUdp.ReceiveAsync(ct).ConfigureAwait(false);
                var source = result.RemoteEndPoint;
                var data = result.Buffer;

                if (clientUdpEndpoint == null || source.Equals(clientUdpEndpoint))
                {
                    // Request from client to destination
                    clientUdpEndpoint ??= source;
                    await HandleUdpClientToDestination(proxyUdp, destinationSockets, data, source, clientEndpoint, ct).ConfigureAwait(false);
                }
                else
                {
                    // This shouldn't happen in normal SOCKS5 UDP flow
                    // Responses come through destination sockets, not the proxy UDP socket
                    _logger?.LogWarning("Received unexpected UDP packet from {Source} for {ClientEndpoint}", source, clientEndpoint);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during cancellation
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error in UDP relay loop for {ClientEndpoint}", clientEndpoint);
        }
        finally
        {
            // Clean up destination sockets
            foreach (var socket in destinationSockets.Values)
            {
                try { socket.Dispose(); } catch { }
            }
        }
    }

    private async Task HandleUdpClientToDestination(UdpClient proxyUdp, Dictionary<System.Net.IPEndPoint, UdpClient> destinationSockets,
        byte[] data, System.Net.IPEndPoint clientEndpoint, string clientDescription, CancellationToken ct)
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
                    var domainLen = data[offset++];
                    var domain = Encoding.UTF8.GetString(data, offset, domainLen);
                    offset += domainLen;

                    var addresses = await Dns.GetHostAddressesAsync(domain, ct).ConfigureAwait(false);
                    destinationAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
                    break;

                default:
                    _logger?.LogWarning("Unsupported address type {AddressType} from {ClientEndpoint}", addressType, clientDescription);
                    return;
            }

            var destinationPort = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            var payload = new byte[data.Length - offset];
            Array.Copy(data, offset, payload, 0, payload.Length);

            var destination = new System.Net.IPEndPoint(destinationAddress, destinationPort);

            // Get or create UDP socket for this destination
            if (!destinationSockets.TryGetValue(destination, out var destSocket))
            {
                destSocket = new UdpClient(destinationAddress.AddressFamily);
                destinationSockets[destination] = destSocket;

                // Start listening for responses from this destination
                _ = Task.Run(() => ListenForDestinationResponseAsync(destSocket, destination, proxyUdp, clientEndpoint, clientDescription, ct), ct);
            }

            // Send raw payload to destination
            await destSocket.SendAsync(payload, destination).ConfigureAwait(false);

            _logger?.LogDebug("Relayed UDP packet from {ClientEndpoint} to {Destination}", clientDescription, destination);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to relay UDP packet from client {ClientEndpoint}", clientDescription);
        }
    }

    private async Task ListenForDestinationResponseAsync(UdpClient destSocket, System.Net.IPEndPoint destination, UdpClient proxyUdp,
        System.Net.IPEndPoint clientEndpoint, string clientDescription, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var result = await destSocket.ReceiveAsync(ct).ConfigureAwait(false);
                var responseData = result.Buffer;

                // Wrap response in SOCKS5 UDP format and send back to client
                var response = BuildUdpResponse(destination, responseData);
                await proxyUdp.SendAsync(response, clientEndpoint).ConfigureAwait(false);

                _logger?.LogDebug("Relayed UDP response from {Destination} to {ClientEndpoint}", destination, clientDescription);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during cancellation
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error listening for responses from {Destination} for {ClientEndpoint}", destination, clientDescription);
        }
    }

    private static async Task PumpStreamsAsync(NetworkStream clientStream, NetworkStream remoteStream, CancellationToken ct)
    {
        const int bufferSize = 4096;
        var tasks = new[]
        {
            CopyStreamAsync(clientStream, remoteStream, bufferSize, ct),
            CopyStreamAsync(remoteStream, clientStream, bufferSize, ct)
        };

        try
        {
            await Task.WhenAny(tasks).ConfigureAwait(false);
        }
        finally
        {
            // Cancel remaining operations
            await Task.WhenAll(tasks.Select(async t =>
            {
                try { await t.ConfigureAwait(false); }
                catch { /* Ignore exceptions during cleanup */ }
            })).ConfigureAwait(false);
        }
    }

    private static async Task CopyStreamAsync(Stream source, Stream destination, int bufferSize, CancellationToken ct)
    {
        var buffer = new byte[bufferSize];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var bytesRead = await source.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (bytesRead == 0) break;

                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), ct).ConfigureAwait(false);
                await destination.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch when (ct.IsCancellationRequested)
        {
            // Expected during cancellation
        }
    }

    private static byte[] BuildUdpResponse(System.Net.IPEndPoint source, byte[] payload)
    {
        var addressBytes = source.Address.GetAddressBytes();
        var header = new byte[3 + 1 + addressBytes.Length + 2];

        header[0] = 0;
        header[1] = 0;
        header[2] = 0;
        header[3] = (byte)(source.Address.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4);

        var offset = 4;
        addressBytes.CopyTo(header, offset);
        offset += addressBytes.Length;

        header[offset++] = (byte)(source.Port >> 8);
        header[offset] = (byte)(source.Port & 0xFF);

        var response = new byte[header.Length + payload.Length];
        Buffer.BlockCopy(header, 0, response, 0, header.Length);
        Buffer.BlockCopy(payload, 0, response, header.Length, payload.Length);

        return response;
    }

    private static async Task<IPEndPoint> ReadDestAsync(NetworkStream stream, Socks5AddressType addressType, CancellationToken ct)
    {
        switch (addressType)
        {
            case Socks5AddressType.IpV4:
                var ipv4Buffer = new byte[6]; // 4 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv4Buffer, ct).ConfigureAwait(false);
                return new IPEndPoint(
                    address: new IPAddress(ipv4Buffer.AsSpan(0, 4)),
                    port: (ipv4Buffer[4] << 8) | ipv4Buffer[5]);

            case Socks5AddressType.IpV6:
                var ipv6Buffer = new byte[18]; // 16 bytes IP + 2 bytes port
                await stream.ReadExactlyAsync(ipv6Buffer, ct).ConfigureAwait(false);
                return new IPEndPoint(
                    address: new IPAddress(ipv6Buffer.AsSpan(0, 16)),
                    port: (ipv6Buffer[16] << 8) | ipv6Buffer[17]);

            case Socks5AddressType.DomainName:
                var lengthBuffer = new byte[1];
                await stream.ReadExactlyAsync(lengthBuffer, ct).ConfigureAwait(false);
                var domainLength = lengthBuffer[0];

                var domainBuffer = new byte[domainLength + 2];
                await stream.ReadExactlyAsync(domainBuffer, ct).ConfigureAwait(false);

                var domain = Encoding.UTF8.GetString(domainBuffer.AsSpan(0, domainLength));
                var port = (domainBuffer[domainLength] << 8) | domainBuffer[domainLength + 1];

                var addresses = await Dns.GetHostAddressesAsync(domain, ct).ConfigureAwait(false);
                var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];

                return new IPEndPoint(address, port);

            default:
                throw new NotSupportedException($"Unsupported address type: {addressType}");
        }
    }

    private static async Task ReplyAsync(NetworkStream stream, Socks5CommandReply reply, IPAddress bindAddress, int bindPort, CancellationToken ct)
    {
        var addressBytes = bindAddress.GetAddressBytes();
        var addressType = bindAddress.AddressFamily == AddressFamily.InterNetworkV6 ? Socks5AddressType.IpV6 : Socks5AddressType.IpV4;

        var response = new byte[4 + addressBytes.Length + 2];
        response[0] = 5; // Version
        response[1] = (byte)reply;
        response[2] = 0; // Reserved
        response[3] = (byte)addressType;

        addressBytes.CopyTo(response, 4);
        response[4 + addressBytes.Length] = (byte)(bindPort >> 8);
        response[4 + addressBytes.Length + 1] = (byte)(bindPort & 0xFF);

        await stream.WriteAsync(response, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        Stop();
        _serverCts.Dispose();
    }
}
