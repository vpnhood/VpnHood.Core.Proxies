using System.Net;
using System.Net.Sockets;

namespace VpnHood.Core.Proxies.Tests.TestHelpers;

/// <summary>
/// A TCP server that reads until EOF and only then echoes everything back.
/// A response can only ever arrive if TCP half-close (client Shutdown(Send))
/// propagates through the proxy chain — this is the half-close litmus test.
/// </summary>
internal sealed class ReadAllThenRespondServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public IPEndPoint EndPoint { get; }

    public ReadAllThenRespondServer(IPAddress address)
    {
        _listener = new TcpListener(new IPEndPoint(address, 0));
        _listener.Start();
        EndPoint = (IPEndPoint)_listener.LocalEndpoint;
        _ = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        try {
            while (!_cts.IsCancellationRequested) {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                _ = Task.Run(() => HandleClientAsync(client));
            }
        }
        catch {
            // ignored
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using var tcp = client;
        try {
            var stream = tcp.GetStream();

            using var received = new MemoryStream();
            var buf = new byte[4096];
            while (true) {
                var n = await stream.ReadAsync(buf, _cts.Token);
                if (n == 0) break; // client half-closed; now respond
                received.Write(buf, 0, n);
            }

            await stream.WriteAsync(received.ToArray(), _cts.Token);
        }
        catch {
            // ignored
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch {
            // ignored
        }
        try { _listener.Stop(); } catch {
            // ignored
        }
        _cts.Dispose();
    }
}
