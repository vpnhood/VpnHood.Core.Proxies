using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace VpnHood.Core.Proxies.HttpProxyServers;

/// <summary>
/// An HTTP CONNECT proxy that requires TLS between the client and the proxy itself.
/// </summary>
public sealed class HttpsProxyServer(
    HttpProxyServerOptions options,
    ILogger<HttpsProxyServer>? logger = null)
    : TcpProxyServerBase(options.ListenEndPoint, options.Backlog, options.MaxConnections, logger)
{
    private readonly X509Certificate2 _serverCertificate = options.ServerCertificate
        ?? throw new ArgumentException("ServerCertificate is required for HTTPS proxy server", nameof(options));

    protected override async Task HandleClientAsync(TcpClient client, CancellationToken serverCancellationToken)
    {
        var clientEndpointAddress = TryGetRemoteEndPoint(client)?.ToString() ?? "unknown";
        Logger.LogDebug("Handling HTTPS client connection from {ClientEndpoint}", clientEndpointAddress);

        using var tcpClient = client;

        try
        {
            tcpClient.NoDelay = true;
            var networkStream = tcpClient.GetStream();

            // Establish TLS connection
            using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

            Logger.LogDebug("Establishing TLS connection with {ClientEndpoint}", clientEndpointAddress);

            using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(serverCancellationToken))
            {
                handshakeCts.CancelAfter(options.HandshakeTimeout);
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, handshakeCts.Token).ConfigureAwait(false);
            }

            Logger.LogDebug("TLS connection established with {ClientEndpoint}", clientEndpointAddress);

            // Perform handshake
            var handshakeResult = await HttpProxyHandler.PerformHandshakeAsync(sslStream, options.Username, options.Password,
                options.HandshakeTimeout, Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            if (!handshakeResult.IsValid)
            {
                return;
            }

            // Handle CONNECT request (HTTPS proxy only supports CONNECT)
            if (handshakeResult.Method == "CONNECT")
            {
                // SslStream hides the socket, so pass it explicitly for half-close propagation
                await HttpProxyHandler.HandleConnectRequestAsync(handshakeResult.Target, sslStream, tcpClient.Client,
                    handshakeResult.Remainder, options.HostConnectionTimeout, options.TunnelHalfCloseTimeout,
                    Logger, clientEndpointAddress, serverCancellationToken).ConfigureAwait(false);
            }
            else
            {
                Logger.LogWarning("Unsupported method {Method} from {ClientEndpoint}", handshakeResult.Method, clientEndpointAddress);
                await HttpProxyHandler.WriteErrorResponseAsync(sslStream, "405 Method Not Allowed", serverCancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            Logger.LogDebug("Client connection cancelled for {ClientEndpoint}", clientEndpointAddress);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Error handling HTTPS client {ClientEndpoint}", clientEndpointAddress);
        }
    }
}
