using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VpnHood.Core.Proxies.HttpProxyServers;

namespace VpnHood.Core.Proxies;

public abstract class TcpProxyServerBase(
    IPEndPoint listerEndPoint,
    int backlog,
    ILogger? logger
) : IDisposable
{
    protected readonly ILogger Logger = logger ?? NullLogger<HttpProxyServer>.Instance;
    private CancellationTokenSource? _serverCts;
    private readonly TcpListener _listener = new TcpListener(listerEndPoint);
    public IPEndPoint ListenerEndPoint => (IPEndPoint)_listener.LocalEndpoint;

    protected abstract object HandleClientAsync(TcpClient client, CancellationToken cancellationToken);
    public bool IsStarted => _serverCts is not null && !_serverCts.IsCancellationRequested;

    public void Start()
    {
        if (IsStarted) return;
        _listener.Start(backlog);
        _serverCts = new CancellationTokenSource();
        _ = Listen(_serverCts.Token);
        Logger.LogInformation("HTTP proxy server started on {EndPoint}", listerEndPoint);
    }

    public void Stop()
    {
        if (!IsStarted) return;
        _serverCts?.Cancel();
        _serverCts = null;
        _listener.Stop();
        Logger.LogInformation("HTTP proxy server stopped");
    }

    private async Task Listen(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                _ = HandleClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception)
            {
                Logger?.LogError(exception, "Error accepting client connection");
            }
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            Stop();
            _serverCts?.Dispose();
            _listener.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}