using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public sealed class HttpsProxyServer(HttpProxyServerOptions options)
{
    private readonly TcpListener _listener = new(options.ListenEndPoint);

    public void Start() => _listener.Start();
    public void Stop() => _listener.Stop();

    public async Task RunAsync(CancellationToken ct)
    {
        Start();
        try {
            while (!ct.IsCancellationRequested) {
                var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }
        finally { Stop(); }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken serverCt)
    {
        using var tcp = client;
        var netStream = tcp.GetStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
        cts.CancelAfter(options.HandshakeTimeout);
        var ct = cts.Token;

        try {
            if (options.ServerCertificate == null)
                throw new InvalidOperationException("ServerCertificate is required.");

            using var ssl = new SslStream(netStream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = options.ServerCertificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, ct).ConfigureAwait(false);

            var reader = new StreamReader(ssl, Encoding.ASCII, leaveOpen: true);
            var writer = new StreamWriter(ssl, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };

            var requestLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine)) return;
            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return;
            var method = parts[0].ToUpperInvariant();

            while (!string.IsNullOrEmpty(await reader.ReadLineAsync(ct).ConfigureAwait(false))) { }

            if (method == "CONNECT") {
                var hp = parts[1].Split(':');
                var host = hp[0];
                var port = hp.Length > 1 && int.TryParse(hp[1], out var p) ? p : 443;
                using var remote = new TcpClient();
                await remote.ConnectAsync(host, port, serverCt).ConfigureAwait(false);
                await writer.WriteLineAsync("HTTP/1.1 200 Connection Established").ConfigureAwait(false);
                await writer.WriteLineAsync().ConfigureAwait(false);
                await writer.FlushAsync().ConfigureAwait(false);
                await PumpAsync(ssl, remote.GetStream(), serverCt).ConfigureAwait(false);
            }
        }
        catch { }
    }

    private static async Task PumpAsync(Stream a, Stream b, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = a.CopyToAsync(b, ct);
        var t2 = b.CopyToAsync(a, ct);
        await Task.WhenAny(t1, t2).ConfigureAwait(false);
        cts.Cancel();
    }
}