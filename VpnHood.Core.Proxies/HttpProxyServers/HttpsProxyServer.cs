using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public sealed class HttpsProxyServer : IDisposable
{
    private readonly HttpProxyServerOptions _options;
    private readonly ILogger<HttpsProxyServer>? _logger;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _serverCts = new();
    private volatile bool _isRunning;

    public HttpsProxyServer(HttpProxyServerOptions options, ILogger<HttpsProxyServer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
        
        if (_options.ServerCertificate == null)
        {
            throw new ArgumentException("ServerCertificate is required for HTTPS proxy server", nameof(options));
        }
        
        _listener = new TcpListener(_options.ListenEndPoint);
    }

    public void Start()
    {
        if (_isRunning) return;
        _listener.Start();
        _isRunning = true;
        _logger?.LogInformation("HTTPS proxy server started on {EndPoint}", _options.ListenEndPoint);
    }

    public void Stop()
    {
        if (!_isRunning) return;
        _isRunning = false;
        _serverCts.Cancel();
        _listener.Stop();
        _logger?.LogInformation("HTTPS proxy server stopped");
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
        _logger?.LogDebug("Handling HTTPS client connection from {ClientEndpoint}", clientEndpoint);

        using var tcp = client;
        
        try
        {
            tcp.NoDelay = true;
            var networkStream = tcp.GetStream();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
            cts.CancelAfter(_options.HandshakeTimeout);
            var ct = cts.Token;

            // Establish TLS connection
            using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);
            
            _logger?.LogDebug("Establishing TLS connection with {ClientEndpoint}", clientEndpoint);
            
            await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _options.ServerCertificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, ct).ConfigureAwait(false);

            _logger?.LogDebug("TLS connection established with {ClientEndpoint}", clientEndpoint);

            var reader = new StreamReader(sslStream, new UTF8Encoding(false), leaveOpen: true);
            var writer = new StreamWriter(sslStream, new UTF8Encoding(false)) { NewLine = "\r\n", AutoFlush = true };

            var requestLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                _logger?.LogWarning("Empty request line from {ClientEndpoint}", clientEndpoint);
                return;
            }

            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                _logger?.LogWarning("Invalid request line from {ClientEndpoint}: {RequestLine}", clientEndpoint, requestLine);
                await WriteErrorResponse(writer, "400 Bad Request", ct).ConfigureAwait(false);
                return;
            }

            var method = parts[0].ToUpperInvariant();
            _logger?.LogDebug("Processing {Method} request from {ClientEndpoint}", method, clientEndpoint);

            // Parse headers
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(ct).ConfigureAwait(false)))
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
                    _logger?.LogWarning("Authentication failed for {ClientEndpoint}", clientEndpoint);
                    await WriteProxyAuthRequiredAsync(writer, ct).ConfigureAwait(false);
                    return;
                }
                _logger?.LogDebug("Authentication successful for {ClientEndpoint}", clientEndpoint);
            }

            // Handle CONNECT request (HTTPS proxy typically only supports CONNECT)
            if (method == "CONNECT")
            {
                await HandleConnectRequest(parts[1], sslStream, writer, serverCt, clientEndpoint).ConfigureAwait(false);
            }
            else
            {
                _logger?.LogWarning("Unsupported method {Method} from {ClientEndpoint}", method, clientEndpoint);
                await WriteErrorResponse(writer, "405 Method Not Allowed", ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            _logger?.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpoint);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error handling HTTPS client {ClientEndpoint}", clientEndpoint);
        }
    }

    private async Task HandleConnectRequest(string authority, SslStream clientStream, StreamWriter writer, CancellationToken ct, string clientEndpoint)
    {
        try
        {
            var parts = authority.Split(':');
            var host = parts[0];
            var port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 443;

            _logger?.LogDebug("Connecting to {Host}:{Port} for {ClientEndpoint}", host, port, clientEndpoint);

            using var remote = new TcpClient();
            remote.NoDelay = true;
            
            // Set connection timeout
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(30));
            
            await remote.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
            
            await writer.WriteLineAsync("HTTP/1.1 200 Connection Established").ConfigureAwait(false);
            await writer.WriteLineAsync().ConfigureAwait(false);
            await writer.FlushAsync(ct).ConfigureAwait(false);

            _logger?.LogDebug("Tunneling established between {ClientEndpoint} and {Host}:{Port}", clientEndpoint, host, port);

            await PumpStreamsAsync(clientStream, remote.GetStream(), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to establish CONNECT tunnel for {ClientEndpoint} to {Authority}", clientEndpoint, authority);
            await WriteErrorResponse(writer, "502 Bad Gateway", ct).ConfigureAwait(false);
        }
    }

    private static bool ValidateBasicAuth(string? proxyAuthHeader, string expectedUser, string expectedPass)
    {
        if (string.IsNullOrEmpty(proxyAuthHeader)) return false;
        
        const string prefix = "Basic ";
        if (!proxyAuthHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;
            
        var b64 = proxyAuthHeader[prefix.Length..].Trim();
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            var colonIndex = decoded.IndexOf(':');
            if (colonIndex < 0) return false;
            
            var username = decoded[..colonIndex];
            var password = decoded[(colonIndex + 1)..];
            
            return string.Equals(username, expectedUser, StringComparison.Ordinal) && 
                   string.Equals(password, expectedPass, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static async Task WriteProxyAuthRequiredAsync(StreamWriter writer, CancellationToken ct)
    {
        await writer.WriteLineAsync("HTTP/1.1 407 Proxy Authentication Required").ConfigureAwait(false);
        await writer.WriteLineAsync("Proxy-Authenticate: Basic realm=\"Proxy\"").ConfigureAwait(false);
        await writer.WriteLineAsync("Connection: close").ConfigureAwait(false);
        await writer.WriteLineAsync("Content-Length: 0").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task WriteErrorResponse(StreamWriter writer, string status, CancellationToken ct)
    {
        await writer.WriteLineAsync($"HTTP/1.1 {status}").ConfigureAwait(false);
        await writer.WriteLineAsync("Connection: close").ConfigureAwait(false);
        await writer.WriteLineAsync("Content-Length: 0").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync(ct).ConfigureAwait(false);
    }

    private static async Task PumpStreamsAsync(Stream source, Stream destination, CancellationToken ct)
    {
        const int bufferSize = 4096;
        var tasks = new[]
        {
            CopyStreamAsync(source, destination, bufferSize, ct),
            CopyStreamAsync(destination, source, bufferSize, ct)
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
        catch (Exception) when (ct.IsCancellationRequested)
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