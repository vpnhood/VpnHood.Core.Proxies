using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace VpnHood.Core.Proxies;

public abstract class TcpProxyServerBase(
    IPEndPoint listenEndPoint,
    int backlog,
    int maxConnections,
    ILogger? logger
) : IDisposable
{
    protected readonly ILogger Logger = logger ?? NullLogger.Instance;
    private readonly Lock _startStopLock = new();
    private CancellationTokenSource? _serverCts;
    private bool _disposed;
    private int _connectionCount;
    private readonly TcpListener _listener = new(listenEndPoint);

    // validated copies of the primary-constructor parameters; MaxConnections = 0 would
    // otherwise silently reject every connection
    private readonly int _backlog = backlog > 0
        ? backlog
        : throw new ArgumentOutOfRangeException(nameof(backlog), backlog, "Backlog must be positive.");
    private readonly int _maxConnections = maxConnections > 0
        ? maxConnections
        : throw new ArgumentOutOfRangeException(nameof(maxConnections), maxConnections, "MaxConnections must be positive.");

    public IPEndPoint ListenerEndPoint => (IPEndPoint)_listener.LocalEndpoint;
    public bool IsStarted => _serverCts is not null;
    public int ActiveConnectionCount => Volatile.Read(ref _connectionCount);

    protected abstract Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken);

    public void Start()
    {
        lock (_startStopLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_serverCts is not null) return;

            _listener.Start(_backlog);
            _serverCts = new CancellationTokenSource();
            _ = ListenAsync(_serverCts.Token);
        }

        Logger.LogInformation("{ServerType} started on {EndPoint}", GetType().Name, ListenerEndPoint);
    }

    public void Stop()
    {
        bool stopped;
        lock (_startStopLock)
        {
            stopped = StopCore();
        }

        if (stopped)
            Logger.LogInformation("{ServerType} stopped", GetType().Name);
    }

    // The whole stop transition runs under _startStopLock (callers hold it): if any part of
    // it (especially _listener.Stop) ran outside, a concurrent Start() could install a fresh
    // listener that this call would then stop, leaving IsStarted true with a dead listener.
    private bool StopCore()
    {
        var serverCts = _serverCts;
        if (serverCts is null) return false;
        _serverCts = null;

        serverCts.Cancel();
        serverCts.Dispose();
        _listener.Stop();
        return true;
    }

    /// <summary>
    /// Starts the server and keeps it running until the token is cancelled.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        Start();
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // graceful shutdown
        }
        finally
        {
            Stop();
        }
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);

                // Hard cap on concurrent connections. Each connection costs buffers, tasks and
                // (for TLS) SslStream internals; without a cap a burst of connections can
                // exhaust a constrained host (e.g. an iOS Network Extension) no matter how
                // cheap each one is.
                if (Interlocked.Increment(ref _connectionCount) > _maxConnections)
                {
                    Interlocked.Decrement(ref _connectionCount);

                    // using guarantees disposal even if logging (endpoint read) throws;
                    // otherwise a reset connection would leak the socket
                    using (client)
                    {
                        Logger.LogWarning("Connection limit ({MaxConnections}) reached; rejecting {ClientEndpoint}",
                            _maxConnections, TryGetRemoteEndPoint(client)?.ToString() ?? "unknown");
                    }
                    continue;
                }

                _ = RunClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception exception)
            {
                Logger.LogError(exception, "Error accepting client connection");
            }
        }
    }

    private async Task RunClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        // The base owns disposal so a handler that throws before reaching its own using
        // statement cannot leak the socket. TcpClient.Dispose is idempotent, so handlers
        // disposing it themselves too is fine.
        using var clientToDispose = client;
        try
        {
            await HandleClientAsync(client, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "Unhandled error in client handler");
        }
        finally
        {
            Interlocked.Decrement(ref _connectionCount);
        }
    }

    /// <summary>
    /// The client's remote endpoint, or null when the connection is already dead — reading
    /// RemoteEndPoint on a reset socket can throw.
    /// </summary>
    protected static IPEndPoint? TryGetRemoteEndPoint(TcpClient client)
    {
        try
        {
            return client.Client.RemoteEndPoint as IPEndPoint;
        }
        catch
        {
            return null;
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            bool stopped;

            // stop and mark disposed in ONE lock acquisition: if the lock were released
            // between the two, a concurrent Start() could slip in, restart the listener and
            // install a new CTS that this disposal would then orphan
            lock (_startStopLock)
            {
                if (_disposed) return;
                _disposed = true;
                stopped = StopCore();
                _listener.Dispose();
            }

            if (stopped)
                Logger.LogInformation("{ServerType} stopped", GetType().Name);
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}
