using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyClients;

public class HttpProxyClient : IProxyClient
{
    private readonly HttpProxyClientOptions _options;
    private readonly ILogger<HttpProxyClient>? _logger;

    public HttpProxyClient(HttpProxyClientOptions options, ILogger<HttpProxyClient>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    public async Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
        => await ConnectAsync(tcpClient, destination.Address.ToString(), destination.Port, cancellationToken).ConfigureAwait(false);

    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);

        _logger?.LogDebug("Connecting to {Host}:{Port} through HTTP proxy {ProxyEndPoint}", host, port, _options.ProxyEndPoint);

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(_options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            Stream stream = tcpClient.GetStream();

            if (_options.UseTls) {
                _logger?.LogDebug("Establishing TLS connection to proxy");
                var ssl = new SslStream(stream, leaveInnerStreamOpen: true, UserCertificateValidationCallback);
                
                var targetHost = _options.ProxyHost ?? _options.ProxyEndPoint.Address.ToString();
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                    TargetHost = targetHost,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellationToken).ConfigureAwait(false);
                
                stream = ssl;
                _logger?.LogDebug("TLS connection established");
            }

            await SendConnectRequest(stream, host, port, cancellationToken).ConfigureAwait(false);
            await ReadConnectResponse(stream, cancellationToken).ConfigureAwait(false);
            
            _logger?.LogDebug("HTTP CONNECT tunnel established to {Host}:{Port}", host, port);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to connect to {Host}:{Port} through HTTP proxy", host, port);
            tcpClient.Close();
            throw;
        }
    }

    private bool UserCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (_options.AllowInvalidCertificates) {
            _logger?.LogWarning("Accepting invalid certificate due to AllowInvalidCertificates option");
            return true;
        }
        
        if (sslPolicyErrors != SslPolicyErrors.None) {
            _logger?.LogWarning("SSL certificate validation failed: {SslPolicyErrors}", sslPolicyErrors);
            return false;
        }
        
        return true;
    }

    private static string BuildAuthority(string host, int port)
    {
        // IPv6 addresses need to be enclosed in brackets
        var isIpv6Literal = host.Contains(':') && host.IndexOf(':') != host.LastIndexOf(':');
        return isIpv6Literal ? $"[{host}]:{port}" : $"{host}:{port}";
    }

    private async Task SendConnectRequest(Stream stream, string host, int port, CancellationToken cancellationToken)
    {
        var authority = BuildAuthority(host, port);
        var requestBuilder = new StringBuilder();
        
        requestBuilder.Append($"CONNECT {authority} HTTP/1.1\r\n");
        requestBuilder.Append($"Host: {authority}\r\n");
        requestBuilder.Append("Connection: keep-alive\r\n");
        
        // Add authentication if provided
        if (_options.Username != null) {
            var credentials = $"{_options.Username}:{_options.Password ?? string.Empty}";
            var encodedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            requestBuilder.Append($"Proxy-Authorization: Basic {encodedCredentials}\r\n");
            _logger?.LogDebug("Added proxy authentication for user: {Username}", _options.Username);
        }
        
        // Add extra headers if provided
        if (_options.ExtraHeaders != null) {
            foreach (var header in _options.ExtraHeaders) {
                requestBuilder.Append($"{header.Key}: {header.Value}\r\n");
            }
        }
        
        requestBuilder.Append("Content-Length: 0\r\n");
        requestBuilder.Append("\r\n");
        
        var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
        await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        
        _logger?.LogDebug("Sent CONNECT request to proxy");
    }

    private async Task ReadConnectResponse(Stream stream, CancellationToken cancellationToken)
    {
        const int maxResponseSize = 8192; // Reasonable limit for HTTP response headers
        var buffer = new byte[maxResponseSize];
        var totalReceived = 0;
        
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30)); // Response timeout
        
        try {
            while (totalReceived < buffer.Length) {
                var bytesRead = await stream.ReadAsync(
                    buffer.AsMemory(totalReceived, buffer.Length - totalReceived), 
                    timeout.Token).ConfigureAwait(false);
                
                if (bytesRead == 0) {
                    throw new IOException("Proxy closed connection before sending complete response");
                }
                
                totalReceived += bytesRead;
                
                // Look for end of HTTP headers (double CRLF)
                if (totalReceived >= 4) {
                    for (var i = 3; i < totalReceived; i++) {
                        if (buffer[i - 3] == '\r' && buffer[i - 2] == '\n' && 
                            buffer[i - 1] == '\r' && buffer[i] == '\n') {
                            var responseText = Encoding.UTF8.GetString(buffer, 0, i + 1);
                            ValidateConnectResponse(responseText);
                            _logger?.LogDebug("Received successful CONNECT response from proxy");
                            return;
                        }
                    }
                }
            }
            
            throw new IOException("HTTP proxy response headers too large");
        }
        catch (OperationCanceledException) when (timeout.Token.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            throw new TimeoutException("Timeout waiting for proxy response");
        }
    }

    private static void ValidateConnectResponse(string responseText)
    {
        // Remove any BOM that might be present
        if (responseText.StartsWith('\ufeff'))
        {
            responseText = responseText[1..];
        }

        var lines = responseText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0)
        {
            throw new IOException("Empty HTTP proxy response");
        }
        
        var statusLine = lines[0];
        var statusParts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        
        if (statusParts.Length < 2)
        {
            throw new IOException($"Invalid HTTP proxy status line: {statusLine}");
        }
        
        if (!statusParts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException($"Invalid HTTP version in proxy response: {statusParts[0]}");
        }
        
        if (!int.TryParse(statusParts[1], out var statusCode))
        {
            throw new IOException($"Invalid HTTP status code in proxy response: {statusParts[1]}");
        }
        
        if (statusCode != 200)
        {
            var reasonPhrase = statusParts.Length > 2 ? statusParts[2] : "Unknown";
            throw new HttpRequestException(
                $"HTTP proxy CONNECT failed with status {statusCode}: {reasonPhrase}", 
                null, 
                (HttpStatusCode)statusCode);
        }
    }
}
