using System.Net.Sockets;
using System.Text;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public sealed class HttpProxyServer(HttpProxyServerOptions options)
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
        var stream = tcp.GetStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(serverCt);
        cts.CancelAfter(options.HandshakeTimeout);
        var ct = cts.Token;

        try {
            var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            var writer = new StreamWriter(stream, Encoding.UTF8) { NewLine = "\r\n", AutoFlush = true };

            var requestLine = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(requestLine)) return;
            var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return;
            var method = parts[0].ToUpperInvariant();

            string? hostHeader = null; string? proxyAuthHeader = null; string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(ct).ConfigureAwait(false))) {
                var idx = line.IndexOf(':');
                if (idx > 0) {
                    var name = line.Substring(0, idx).Trim();
                    var value = line.Substring(idx + 1).Trim();
                    if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) hostHeader = value;
                    else if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase)) proxyAuthHeader = value;
                }
            }

            if (options.Username != null) {
                if (!ValidateBasicAuth(proxyAuthHeader, options.Username, options.Password ?? string.Empty)) {
                    await WriteProxyAuthRequiredAsync(writer, ct).ConfigureAwait(false);
                    return;
                }
            }

            if (method == "CONNECT") {
                var authority = parts[1];
                var hp = authority.Split(':');
                var host = hp[0];
                var port = hp.Length > 1 && int.TryParse(hp[1], out var p) ? p : 443;
                using var remote = new TcpClient();
                await remote.ConnectAsync(host, port, serverCt).ConfigureAwait(false);
                await writer.WriteLineAsync("HTTP/1.1 200 Connection Established").ConfigureAwait(false);
                await writer.WriteLineAsync().ConfigureAwait(false);
                await writer.FlushAsync().ConfigureAwait(false);
                await PumpAsync(stream, remote.GetStream(), serverCt).ConfigureAwait(false);
                return;
            }
            else {
                var uri = new Uri(parts[1], UriKind.Absolute);
                var host = string.IsNullOrEmpty(uri.Host) ? hostHeader ?? throw new InvalidOperationException("Host header required.") : uri.Host;
                var port = uri.IsDefaultPort ? (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80) : uri.Port;
                using var remote = new TcpClient();
                await remote.ConnectAsync(host, port, serverCt).ConfigureAwait(false);
                var remoteStream = remote.GetStream();
                var reqBuilder = new StringBuilder();
                reqBuilder.Append(method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
                if (hostHeader == null) reqBuilder.Append("Host: ").Append(host).Append(":").Append(port).Append("\r\n");
                reqBuilder.Append("Connection: close\r\n\r\n");
                var bytes = Encoding.UTF8.GetBytes(reqBuilder.ToString());
                await remoteStream.WriteAsync(bytes, serverCt).ConfigureAwait(false);
                await remoteStream.FlushAsync(serverCt).ConfigureAwait(false);
                await PumpAsync(remoteStream, stream, serverCt).ConfigureAwait(false);
                return;
            }
        }
        catch { }
    }

    private static bool ValidateBasicAuth(string? proxyAuthHeader, string expectedUser, string expectedPass)
    {
        if (string.IsNullOrEmpty(proxyAuthHeader)) return false;
        // expected format: "Basic base64(username:password)"
        const string prefix = "Basic ";
        if (!proxyAuthHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;
        var b64 = proxyAuthHeader[prefix.Length..].Trim();
        try {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            var sep = decoded.IndexOf(':');
            if (sep < 0) return false;
            var u = decoded[..sep];
            var p = decoded[(sep + 1)..];
            return string.Equals(u, expectedUser, StringComparison.Ordinal) && string.Equals(p, expectedPass, StringComparison.Ordinal);
        }
        catch {
            return false;
        }
    }

    private static async Task WriteProxyAuthRequiredAsync(StreamWriter writer, CancellationToken ct)
    {
        await writer.WriteLineAsync("HTTP/1.1 407 Proxy Authentication Required").ConfigureAwait(false);
        await writer.WriteLineAsync("Proxy-Authenticate: Basic realm=\"Proxy\"").ConfigureAwait(false);
        await writer.WriteLineAsync("Connection: close").ConfigureAwait(false);
        await writer.WriteLineAsync().ConfigureAwait(false);
        await writer.FlushAsync().ConfigureAwait(false);
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