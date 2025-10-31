using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyClients;

public class HttpProxyClient(
    HttpProxyClientOptions options, 
    ILogger<HttpProxyClient>? logger = null)
    : IProxyClient
{
    
    public async Task ConnectAsync(TcpClient tcpClient, IPEndPoint destination, CancellationToken cancellationToken)
        => await ConnectAsync(tcpClient, destination.Address.ToString(), destination.Port, cancellationToken).ConfigureAwait(false);

    public IPEndPoint ProxyEndPoint => options.ProxyEndPoint;

    public async Task ConnectAsync(TcpClient tcpClient, string host, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);

        logger?.LogDebug("Connecting to {Host}:{Port} through HTTP proxy {ProxyEndPoint}", host, port, options.ProxyEndPoint);

        try {
            if (!tcpClient.Connected) {
                tcpClient.NoDelay = true;
                await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);
            }

            Stream stream = tcpClient.GetStream();

            if (options.UseTls) {
                logger?.LogDebug("Establishing TLS connection to proxy");
                var ssl = new SslStream(stream, leaveInnerStreamOpen: true, UserCertificateValidationCallback);
                
                var targetHost = options.ProxyHost ?? options.ProxyEndPoint.Address.ToString();
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                    TargetHost = targetHost,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellationToken).ConfigureAwait(false);
                
                stream = ssl;
                logger?.LogDebug("TLS connection established");
            }

            await SendConnectRequest(stream, host, port, cancellationToken).ConfigureAwait(false);
            await ReadConnectResponse(stream, cancellationToken).ConfigureAwait(false);
            
            logger?.LogDebug("HTTP CONNECT tunnel established to {Host}:{Port}", host, port);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to connect to {Host}:{Port} through HTTP proxy", host, port);
            tcpClient.Close();
            throw;
        }
    }

    public async Task CheckConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(tcpClient);
        try {
            tcpClient.NoDelay = true;
            await tcpClient.ConnectAsync(options.ProxyEndPoint, cancellationToken).ConfigureAwait(false);

            if (options.UseTls) {
                var networkStream = tcpClient.GetStream();
                var ssl = new SslStream(networkStream, leaveInnerStreamOpen: true, UserCertificateValidationCallback);
                var targetHost = options.ProxyHost ?? options.ProxyEndPoint.Address.ToString();
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                    TargetHost = targetHost,
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellationToken).ConfigureAwait(false);
            }
        }
        catch {
            tcpClient.Close();
            throw;
        }
    }

    private bool UserCertificateValidationCallback(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (options.AllowInvalidCertificates) {
            logger?.LogWarning("Accepting invalid certificate due to AllowInvalidCertificates option");
            return true;
        }
        
        if (sslPolicyErrors != SslPolicyErrors.None) {
            logger?.LogWarning("SSL certificate validation failed: {SslPolicyErrors}", sslPolicyErrors);
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
        if (options.Username != null) {
            var credentials = $"{options.Username}:{options.Password ?? string.Empty}";
            var encodedCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            requestBuilder.Append($"Proxy-Authorization: Basic {encodedCredentials}\r\n");
            logger?.LogDebug("Added proxy authentication for user: {Username}", options.Username);
        }
        
        // Add extra headers if provided
        if (options.ExtraHeaders != null) {
            foreach (var header in options.ExtraHeaders) {
                requestBuilder.Append($"{header.Key}: {header.Value}\r\n");
            }
        }
        
        requestBuilder.Append("Content-Length: 0\r\n");
        requestBuilder.Append("\r\n");
        
        var requestBytes = Encoding.UTF8.GetBytes(requestBuilder.ToString());
        await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        
        logger?.LogDebug("Sent CONNECT request to proxy");
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
                
                if (bytesRead == 0) 
                    throw new IOException("Proxy closed connection before sending complete response");
                
                totalReceived += bytesRead;
                
                // Look for end of HTTP headers (double CRLF)
                if (totalReceived >= 4) {
                    for (var i = 3; i < totalReceived; i++) {
                        if (buffer[i - 3] == '\r' && buffer[i - 2] == '\n' && 
                            buffer[i - 1] == '\r' && buffer[i] == '\n') {
                            var responseText = Encoding.UTF8.GetString(buffer, 0, i + 1);
                            ValidateConnectResponse(responseText);
                            logger?.LogDebug("Received successful CONNECT response from proxy");
                            return;
                        }
                    }
                }
            }
            
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "HTTP proxy response headers too large");
        }
        catch (OperationCanceledException) when (timeout.Token.IsCancellationRequested && !cancellationToken.IsCancellationRequested) {
            throw new TimeoutException("Timeout waiting for proxy response");
        }
    }

    private static void ValidateConnectResponse(string responseText)
    {
        if (string.IsNullOrWhiteSpace(responseText))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Empty or non-HTTP response");

        // Remove BOM if present
        if (responseText[0] == '\ufeff')
            responseText = responseText[1..];

        if (!responseText.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Not an HTTP proxy");

        var lines = responseText.Split(new[] { "\r\n" }, StringSplitOptions.None);
        var parts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var code))
            throw new ProxyClientException(SocketError.ProtocolNotSupported, "Malformed HTTP status line");

        if (code == 200)
            return;

        var reason = parts.Length > 2 ? parts[2] : "Unknown";

        throw code switch {
            // Valid proxy, needs or failed auth
            407 => new ProxyClientException(SocketError.AccessDenied,
                $"Proxy authentication required or failed (status {code}: {reason})"),

            // Proxy timeout (client-side or idle)
            408 => new ProxyClientException(SocketError.TimedOut,
                $"Proxy connection timed out (status {code}: {reason})"),

            // Target or proxy host not found
            404 => new ProxyClientException(SocketError.HostNotFound,
                $"HTTP proxy or target not found (status {code}: {reason})"),

            // CONNECT disallowed or plain HTTP server
            400 or 401 or 403 or 405 => new ProxyClientException(SocketError.ProtocolNotSupported,
                $"HTTP server does not support CONNECT (status {code}: {reason})"),

            // Upstream errors: proxy could not reach target
            500 or 502 or 503 or 504 => new ProxyClientException(SocketError.HostUnreachable,
                $"Proxy failed to connect to target (status {code}: {reason})"),

            // Rate limits or custom non-standard responses
            429 => new ProxyClientException(SocketError.TryAgain,
                $"Proxy rate limited request (status {code}: {reason})"),

            // Everything else: generic proxy failure
            _ => new ProxyClientException(SocketError.SocketError,
                $"Unexpected HTTP proxy response (status {code}: {reason})")
        };

    }


}
