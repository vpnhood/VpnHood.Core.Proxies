using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public sealed class HttpProxyServer : IDisposable
{
    private readonly HttpProxyServerOptions _options;
    private readonly ILogger<HttpProxyServer>? _logger;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _serverCts = new();
    private volatile bool _isRunning;

    public HttpProxyServer(HttpProxyServerOptions options, ILogger<HttpProxyServer>? logger = null)
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
        _logger?.LogInformation("HTTP proxy server started on {EndPoint}", _options.ListenEndPoint);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _serverCts.Cancel();
        _listener.Stop();
        _logger?.LogInformation("HTTP proxy server stopped");
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _serverCts.Token);
        var operationCancellationToken = linkedCts.Token;

        Start();
        try
        {
            while (!operationCancellationToken.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(operationCancellationToken).ConfigureAwait(false);
                    _ = Task.Run(() => HandleClientAsync(client, operationCancellationToken), operationCancellationToken);
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

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellationToken)
    {
        var clientEndpointAddress = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _logger?.LogDebug("Handling client connection from {ClientEndpoint}", clientEndpointAddress);

        using var tcpClient = client;

        try
        {
            tcpClient.NoDelay = true;
            var networkStream = tcpClient.GetStream();

            var reader = new StreamReader(networkStream, new UTF8Encoding(false), leaveOpen: true);
            var writer = new StreamWriter(networkStream, new UTF8Encoding(false)) { NewLine = "\r\n", AutoFlush = true };

            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
            handshakeCts.CancelAfter(_options.HandshakeTimeout);
            var handshakeCancellationToken = handshakeCts.Token;

            var requestLine = await reader.ReadLineAsync(handshakeCancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                _logger?.LogWarning("Empty request line from {ClientEndpoint}", clientEndpointAddress);
                return;
            }

            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                _logger?.LogWarning("Invalid request line from {ClientEndpoint}: {RequestLine}", clientEndpointAddress, requestLine);
                await WriteErrorResponse(writer, "400 Bad Request", handshakeCancellationToken).ConfigureAwait(false);
                return;
            }

            var method = parts[0].ToUpperInvariant();
            _logger?.LogDebug("Processing {Method} request from {ClientEndpoint}", method, clientEndpointAddress);

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
            if (_options.Username != null)
            {
                if (!ValidateBasicAuth(headers.GetValueOrDefault("Proxy-Authorization"), _options.Username, _options.Password ?? string.Empty))
                {
                    _logger?.LogWarning("Authentication failed for {ClientEndpoint}", clientEndpointAddress);
                    await WriteProxyAuthRequiredAsync(writer, handshakeCancellationToken).ConfigureAwait(false);
                    return;
                }
                _logger?.LogDebug("Authentication successful for {ClientEndpoint}", clientEndpointAddress);
            }

            // Handle request
            if (method == "CONNECT")
            {
                await HandleConnectRequestAsync(parts[1], networkStream, writer, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            }
            else
            {
                await HandleHttpRequestAsync(method, parts[1], headers, networkStream, serverCancellationToken, clientEndpointAddress).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            var a = new NullLogger<OperationCanceledException>();
            _logger?.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Error handling client {ClientEndpoint}", clientEndpointAddress);
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

            _logger?.LogDebug("Connecting to {Host}:{Port} for {ClientEndpoint}", hostname, port, clientEndpointAddress);

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            // Set connection timeout
            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(_options.HostConnectionTimeout);
                await remoteClient.ConnectAsync(hostname, port, connectionCts.Token).ConfigureAwait(false);
            }

            await writer.WriteLineAsync("HTTP/1.1 200 Connection Established").ConfigureAwait(false);
            await writer.WriteLineAsync().ConfigureAwait(false);
            await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

            _logger?.LogDebug("Tunneling established between {ClientEndpoint} and {Host}:{Port}", clientEndpointAddress, hostname, port);

            await PumpStreamsAsync(clientStream, remoteClient.GetStream(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            _logger?.LogError(exception, "Failed to establish CONNECT tunnel for {ClientEndpoint} to {Authority}", clientEndpointAddress, authority);
            await WriteErrorResponse(writer, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleHttpRequestAsync(string method, string uri, Dictionary<string, string> headers, Stream clientStream, CancellationToken cancellationToken, string clientEndpointAddress)
    {
        try
        {
            if (!Uri.TryCreate(uri, UriKind.Absolute, out var targetUri))
            {
                _logger?.LogWarning("Invalid URI {Uri} from {ClientEndpoint}", uri, clientEndpointAddress);
                await WriteErrorResponse(new StreamWriter(clientStream, Encoding.UTF8) { AutoFlush = true }, "400 Bad Request", cancellationToken).ConfigureAwait(false);
                return;
            }

            var hostname = targetUri.Host;
            var port = targetUri.IsDefaultPort ? targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80 : targetUri.Port;

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(_options.HostConnectionTimeout);
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
            _logger?.LogError(exception, "Failed to handle HTTP request for {ClientEndpoint}", clientEndpointAddress);
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

    public void Dispose()
    {
        Stop();
        _serverCts.Dispose();
    }
}