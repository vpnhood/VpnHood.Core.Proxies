using System.Net;
using System.Net.Sockets;
using System.Text;

namespace VpnHood.Core.Proxies.Tests.TestHelpers;

/// <summary>
/// A minimal HTTP origin server that captures the request it receives and replies
/// "200 OK" with a fixed body. Used to verify what a proxy actually forwards.
/// </summary>
internal sealed class HttpOriginServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource _requestReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public IPEndPoint EndPoint { get; }
    public string ReceivedHeaders { get; private set; } = string.Empty;
    public byte[] ReceivedBody { get; private set; } = [];
    public Task RequestReceived => _requestReceived.Task;

    public HttpOriginServer(IPAddress address)
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

            // read headers byte by byte until CRLFCRLF
            var headerBytes = new List<byte>();
            var one = new byte[1];
            while (true) {
                var n = await stream.ReadAsync(one, _cts.Token);
                if (n == 0) return;
                headerBytes.Add(one[0]);
                if (headerBytes.Count >= 4 &&
                    headerBytes[^4] == '\r' && headerBytes[^3] == '\n' &&
                    headerBytes[^2] == '\r' && headerBytes[^1] == '\n')
                    break;
            }

            ReceivedHeaders = Encoding.ASCII.GetString(headerBytes.ToArray());

            // read the body if Content-Length is present
            var contentLength = 0;
            foreach (var line in ReceivedHeaders.Split("\r\n")) {
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    contentLength = int.Parse(line[15..].Trim());
            }

            if (contentLength > 0) {
                var body = new byte[contentLength];
                await stream.ReadExactlyAsync(body, _cts.Token);
                ReceivedBody = body;
            }

            _requestReceived.TrySetResult();

            var response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray();
            await stream.WriteAsync(response, _cts.Token);
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
