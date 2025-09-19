using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public sealed class HttpProxyServer(
    HttpProxyServerOptions options, 
    ILogger<HttpProxyServer>? logger = null) 
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, logger)
{
    protected override async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellationToken)
    {
        var clientEndpointAddress = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        Logger.LogDebug("Handling client connection from {ClientEndpoint}", clientEndpointAddress);

        using var tcpClient = client;

        try
        {
            tcpClient.NoDelay = true;
            var networkStream = tcpClient.GetStream();

            // Perform handshake
            var handshakeResult = await PerformHandshakeAsync(networkStream, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
            {
                return;
            }

            // Handle request based on method
            if (handshakeResult.Method == "CONNECT")
            {
                await HandleConnectRequestAsync(handshakeResult.Target, networkStream, handshakeResult.Writer, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            }
            else
            {
                await HandleHttpRequestAsync(handshakeResult.Method, handshakeResult.Target, handshakeResult.Headers, networkStream, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling client {ClientEndpoint}", clientEndpointAddress);
        }
    }

    private async Task<HttpHandshakeResult> PerformHandshakeAsync(Stream networkStream, CancellationToken serverCancellationToken, string clientEndpointAddress)
    {
        var reader = new StreamReader(networkStream, new UTF8Encoding(false), leaveOpen: true);
        var writer = new StreamWriter(networkStream, new UTF8Encoding(false)) { NewLine = "\r\n", AutoFlush = true };

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
        handshakeCts.CancelAfter(options.HandshakeTimeout);
        var handshakeCancellationToken = handshakeCts.Token;

        try
        {
            // Read request line
            var requestLine = await reader.ReadLineAsync(handshakeCancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                Logger.LogWarning("Empty request line from {ClientEndpoint}", clientEndpointAddress);
                return HttpHandshakeResult.Invalid;
            }

            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                Logger.LogWarning("Invalid request line from {ClientEndpoint}: {RequestLine}", clientEndpointAddress, requestLine);
                await WriteErrorResponse(writer, "400 Bad Request", handshakeCancellationToken).ConfigureAwait(false);
                return HttpHandshakeResult.Invalid;
            }

            var method = parts[0].ToUpperInvariant();
            var target = parts[1];

            Logger.LogDebug("Processing {Method} request from {ClientEndpoint}", method, clientEndpointAddress);

            // Parse headers
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(handshakeCancellationToken).ConfigureAwait(false)))
            {
                var colonIndex = line.IndexOf(':');
                if (colonIndex > 0)
                {
                    var name = line[..colonIndex].Trim();
                    var value = line[(colonIndex + 1)..].Trim();
                    headers[name] = value;
                }
            }

            // Check authentication
            if (options.Username != null)
            {
                if (!ValidateBasicAuth(headers.GetValueOrDefault("Proxy-Authorization"), options.Username, options.Password ?? string.Empty))
                {
                    Logger.LogWarning("Authentication failed for {ClientEndpoint}", clientEndpointAddress);
                    await WriteProxyAuthRequiredAsync(writer, handshakeCancellationToken).ConfigureAwait(false);
                    return HttpHandshakeResult.Invalid;
                }
                Logger.LogDebug("Authentication successful for {ClientEndpoint}", clientEndpointAddress);
            }

            return HttpHandshakeResult.Valid(method, target, headers, reader, writer);
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Handshake cancelled for {ClientEndpoint}", clientEndpointAddress);
            return HttpHandshakeResult.Invalid;
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error during handshake for {ClientEndpoint}", clientEndpointAddress);
            return HttpHandshakeResult.Invalid;
        }
    }

    private async Task HandleConnectRequestAsync(string authority, Stream clientStream,
        StreamWriter writer, CancellationToken cancellationToken, string clientEndpointAddress)
    {
        try
        {
            var parts = authority.Split(':');
            var hostname = parts[0];
            var port = parts.Length > 1 && int.TryParse(parts[1], out var parsedPort) ? parsedPort : 443;

            Logger.LogDebug("Connecting to {Host}:{Port} for {ClientEndpoint}", hostname, port, clientEndpointAddress);

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            // Set connection timeout
            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(hostname, port, connectionCts.Token).ConfigureAwait(false);
            }

            await writer.WriteLineAsync("HTTP/1.1 200 Connection Established").ConfigureAwait(false);
            await writer.WriteLineAsync().ConfigureAwait(false);
            await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

            Logger.LogDebug("Tunneling established between {ClientEndpoint} and {Host}:{Port}", clientEndpointAddress, hostname, port);

            await PumpStreamsAsync(clientStream, remoteClient.GetStream(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Failed to establish CONNECT tunnel for {ClientEndpoint} to {Authority}", clientEndpointAddress, authority);
            await WriteErrorResponse(writer, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleHttpRequestAsync(string method, string uri, Dictionary<string, string> headers, Stream clientStream, CancellationToken cancellationToken, string clientEndpointAddress)
    {
        try
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var targetUri))
            {
                Logger.LogWarning("Invalid URI {Uri} from {ClientEndpoint}", uri, clientEndpointAddress);
                await WriteErrorResponse(new StreamWriter(clientStream, Encoding.UTF8) { AutoFlush = true }, "400 Bad Request", cancellationToken).ConfigureAwait(false);
                return;
            }

            var hostname = targetUri.Host;
            var port = targetUri.IsDefaultPort ? targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80 : targetUri.Port;

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(hostname, port, connectionCts.Token).ConfigureAwait(false);
            }

            var remoteStream = remoteClient.GetStream();

            // Forward the request
            var requestBuilder = new StringBuilder();
            requestBuilder.Append(method).Append(' ').Append(targetUri.PathAndQuery).Append(" HTTP/1.1\r\n");

            // Add/modify headers
            if (!headers.ContainsKey("Host"))
                requestBuilder.Append("Host: ").Append(hostname).Append(':').Append(port).Append("\r\n");

            requestBuilder.Append("Connection: close\r\n\r\n");

            var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
            await remoteStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
            await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            await PumpStreamsAsync(remoteStream, clientStream, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Failed to handle HTTP request for {ClientEndpoint}", clientEndpointAddress);
        }
    }

    private static bool ValidateBasicAuth(string? proxyAuthHeader, string expectedUsername, string expectedPassword)
    {
        if (string.IsNullOrEmpty(proxyAuthHeader)) return false;

        const string prefix = "Basic ";
        if (!proxyAuthHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var base64Credentials = proxyAuthHeader[prefix.Length..].Trim();
        try
        {
            var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(base64Credentials));
            var colonIndex = decodedCredentials.IndexOf(':');
            if (colonIndex < 0) return false;

            var username = decodedCredentials[..colonIndex];
            var password = decodedCredentials[(colonIndex + 1)..];

            return string.Equals(username, expectedUsername, StringComparison.Ordinal) &&
                   string.Equals(password, expectedPassword, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static async Task WriteProxyAuthRequiredAsync(StreamWriter writer, CancellationToken cancellationToken)
    {
        await writer.WriteLineAsync("HTTP/1.1 407 Proxy Authentication Required").ConfigureAwait(false);
        await writer.WriteLineAsync("Proxy-Authenticate: Basic realm=\"Proxy\"").ConfigureAwait(false);
        await writer.WriteLineAsync("Connection: close").ConfigureAwait(false);
        await writer.WriteLineAsync("Content-Length: 0").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteErrorResponse(StreamWriter writer, string status, CancellationToken cancellationToken)
    {
        await writer.WriteLineAsync($"HTTP/1.1 {status}").ConfigureAwait(false);
        await writer.WriteLineAsync("Connection: close").ConfigureAwait(false);
        await writer.WriteLineAsync("Content-Length: 0").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task PumpStreamsAsync(Stream sourceStream, Stream destinationStream, CancellationToken cancellationToken)
    {
        const int bufferSize = 4096;
        var tasks = new[]
        {
            CopyStreamAsync(sourceStream, destinationStream, bufferSize, cancellationToken),
            CopyStreamAsync(destinationStream, sourceStream, bufferSize, cancellationToken)
        };

        try
        {
            await Task.WhenAny(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected when cancellation is requested
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
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during cancellation
        }
    }
}