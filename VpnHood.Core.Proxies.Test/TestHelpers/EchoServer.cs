using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnHood.Core.Proxies.Test.TestHelpers;

internal sealed class EchoServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public IPEndPoint EndPoint { get; }

    public EchoServer(IPAddress address)
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
        catch { }
    }

    private static async Task HandleClientAsync(TcpClient client)
    {
        using var tcp = client;
        var stream = tcp.GetStream();
        var buf = new byte[4096];
        try {
            while (true) {
                var n = await stream.ReadAsync(buf);
                if (n <= 0) break;
                await stream.WriteAsync(buf.AsMemory(0, n));
            }
        }
        catch { }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _listener.Stop(); } catch { }
        _cts.Dispose();
    }
}
