using System.Net;
using System.Net.Sockets;

namespace VpnHood.Core.Proxies.Tests.TestHelpers;

/// <summary>
/// A TCP server that speaks first: it sends a banner immediately after accepting a
/// connection (like SMTP or SSH), then echoes whatever it receives.
/// </summary>
internal sealed class BannerServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public IPEndPoint EndPoint { get; }
    public byte[] Banner { get; }

    public BannerServer(IPAddress address, byte[] banner)
    {
        Banner = banner;
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
            await stream.WriteAsync(Banner, _cts.Token);

            var buf = new byte[4096];
            while (true) {
                var n = await stream.ReadAsync(buf, _cts.Token);
                if (n <= 0) break;
                await stream.WriteAsync(buf.AsMemory(0, n), _cts.Token);
            }
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
