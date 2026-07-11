using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyServers;

/// <summary>
/// Request parsing and CONNECT handling shared by <see cref="HttpProxyServer"/> and <see cref="HttpsProxyServer"/>.
/// </summary>
internal static class HttpProxyHandler
{
    public static async Task<HttpHandshakeResult> PerformHandshakeAsync(Stream stream, string? username, string? password,
        TimeSpan handshakeTimeout, ILogger logger, string clientEndpointAddress, CancellationToken serverCancellationToken)
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken);
        handshakeCts.CancelAfter(handshakeTimeout);
        var cancellationToken = handshakeCts.Token;

        using var reader = new HttpHandshakeReader(stream);
        try
        {
            // Read request line
            var requestLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine))
            {
                logger.LogWarning("Empty request line from {ClientEndpoint}", clientEndpointAddress);
                return HttpHandshakeResult.Invalid;
            }

            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                logger.LogWarning("Invalid request line from {ClientEndpoint}: {RequestLine}", clientEndpointAddress, requestLine);
                await WriteErrorResponseAsync(stream, "400 Bad Request", cancellationToken).ConfigureAwait(false);
                return HttpHandshakeResult.Invalid;
            }

            var method = parts[0].ToUpperInvariant();
            var target = parts[1];

            logger.LogDebug("Processing {Method} request from {ClientEndpoint}", method, clientEndpointAddress);

            var headers = await reader.ReadHeadersAsync(cancellationToken).ConfigureAwait(false);

            // Check authentication
            if (username != null)
            {
                if (!ValidateBasicAuth(headers.GetValueOrDefault("Proxy-Authorization"), username, password ?? string.Empty))
                {
                    logger.LogWarning("Authentication failed for {ClientEndpoint}", clientEndpointAddress);
                    await WriteProxyAuthRequiredAsync(stream, cancellationToken).ConfigureAwait(false);
                    return HttpHandshakeResult.Invalid;
                }
                logger.LogDebug("Authentication successful for {ClientEndpoint}", clientEndpointAddress);
            }

            return HttpHandshakeResult.Valid(method, target, headers, reader.DetachRemainder());
        }
        catch (OperationCanceledException)
        {
            logger.LogDebug("Handshake cancelled for {ClientEndpoint}", clientEndpointAddress);
            return HttpHandshakeResult.Invalid;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Error during handshake for {ClientEndpoint}", clientEndpointAddress);
            return HttpHandshakeResult.Invalid;
        }
    }

    public static async Task HandleConnectRequestAsync(string authority, Stream clientStream, Socket? clientSocket,
        ReadOnlyMemory<byte> clientPrefix, TimeSpan hostConnectionTimeout, TimeSpan halfCloseTimeout,
        ILogger logger, string clientEndpointAddress, CancellationToken cancellationToken)
    {
        if (!TryParseAuthority(authority, out var hostname, out var port))
        {
            logger.LogWarning("Invalid CONNECT authority {Authority} from {ClientEndpoint}", authority, clientEndpointAddress);
            await WriteErrorResponseAsync(clientStream, "400 Bad Request", cancellationToken).ConfigureAwait(false);
            return;
        }

        var tunnelEstablished = false;
        try
        {
            logger.LogDebug("Connecting to {Host}:{Port} for {ClientEndpoint}", hostname, port, clientEndpointAddress);

            using var remoteClient = new TcpClient();
            remoteClient.NoDelay = true;

            // Set connection timeout
            using (var connectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectionCts.CancelAfter(hostConnectionTimeout);
                await remoteClient.ConnectAsync(hostname, port, connectionCts.Token).ConfigureAwait(false);
            }

            await WriteRawResponseAsync(clientStream, "HTTP/1.1 200 Connection Established\r\n\r\n", cancellationToken).ConfigureAwait(false);
            tunnelEstablished = true;

            logger.LogDebug("Tunneling established between {ClientEndpoint} and {Host}:{Port}", clientEndpointAddress, hostname, port);

            await ProxyStreamPump.PumpStreamsAsync(clientStream, remoteClient.GetStream(), halfCloseTimeout, cancellationToken,
                clientSocket, remoteClient.Client, clientPrefix).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Failed to establish CONNECT tunnel for {ClientEndpoint} to {Authority}", clientEndpointAddress, authority);

            // don't corrupt the tunnel with an HTTP error once the 200 response has been sent
            if (!tunnelEstablished)
                await WriteErrorResponseAsync(clientStream, "502 Bad Gateway", cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Parses a CONNECT authority ("host:port", "ipv4:port" or "[ipv6]:port"). The port defaults to 443.
    /// </summary>
    public static bool TryParseAuthority(string authority, out string host, out int port)
    {
        host = string.Empty;
        port = 443;

        if (string.IsNullOrWhiteSpace(authority))
            return false;

        // Bracketed IPv6 literal: [::1]:443
        if (authority[0] == '[')
        {
            var closingBracket = authority.IndexOf(']');
            if (closingBracket < 2)
                return false;

            host = authority[1..closingBracket];
            var remainder = authority[(closingBracket + 1)..];
            if (remainder.Length == 0)
                return IPAddress.TryParse(host, out _);

            return remainder[0] == ':' &&
                   int.TryParse(remainder[1..], out port) && port is >= 1 and <= 65535 &&
                   IPAddress.TryParse(host, out _);
        }

        var lastColon = authority.LastIndexOf(':');
        if (lastColon < 0)
        {
            host = authority;
            return true;
        }

        // More than one colon without brackets: a raw IPv6 literal without a port
        if (authority.IndexOf(':') != lastColon)
        {
            host = authority;
            return IPAddress.TryParse(authority, out _);
        }

        host = authority[..lastColon];
        return host.Length > 0 && int.TryParse(authority[(lastColon + 1)..], out port) && port is >= 1 and <= 65535;
    }

    public static bool ValidateBasicAuth(string? proxyAuthHeader, string expectedUsername, string expectedPassword)
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

    public static Task WriteProxyAuthRequiredAsync(Stream stream, CancellationToken cancellationToken) =>
        WriteRawResponseAsync(stream,
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            cancellationToken);

    public static Task WriteErrorResponseAsync(Stream stream, string status, CancellationToken cancellationToken) =>
        WriteRawResponseAsync(stream, $"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", cancellationToken);

    private static async Task WriteRawResponseAsync(Stream stream, string response, CancellationToken cancellationToken)
    {
        var responseBytes = Encoding.ASCII.GetBytes(response);
        await stream.WriteAsync(responseBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
