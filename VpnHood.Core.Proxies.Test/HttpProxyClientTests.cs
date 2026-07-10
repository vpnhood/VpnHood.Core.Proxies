using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.HttpProxyClients;
using VpnHood.Core.Proxies.HttpProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class HttpProxyClientTests
{
    private static Task<HttpProxyServer> StartHttpProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new HttpProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new HttpProxyServer(serverOptions);
        server.Start();
        return Task.FromResult(server);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            Username = "u",
            Password = "p",
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);

        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        var ex = await Assert.ThrowsExceptionAsync<ProxyClientException>(() => 
            client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None)
        );
        Assert.AreEqual(SocketError.AccessDenied, ex.SocketErrorCode);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(); // No auth required

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = "hello no auth"u8.ToArray();
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);

        CollectionAssert.AreEqual(payload, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartHttpProxyAsync(user: "u", pass: "p");

        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            Username = "wrong",
            Password = "credentials",
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        var ex = await Assert.ThrowsExceptionAsync<ProxyClientException>(() =>
            client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None)
        );
        Assert.AreEqual(SocketError.AccessDenied, ex.SocketErrorCode);
    }

    [TestMethod]
    public async Task HttpProxy_CheckConnection_Succeeds()
    {
        using var server = await StartHttpProxyAsync(); // No auth required
        var clientOptions = new HttpProxyClientOptions
        {
            ProxyEndPoint = server.ListenerEndPoint,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_ServerSpeaksFirst_BannerIsPreserved()
    {
        // regression: bytes the destination sends right after the tunnel opens (SMTP/SSH
        // banners) must not be swallowed while reading the CONNECT response
        var banner = "220 welcome to the banner server\r\n"u8.ToArray();
        using var bannerServer = new BannerServer(IPAddress.Loopback, banner);
        using var server = await StartHttpProxyAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint });
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, bannerServer.EndPoint.Address.ToString(), bannerServer.EndPoint.Port, cts.Token);

        var stream = tcp.GetStream();
        var buf = new byte[banner.Length];
        await stream.ReadExactlyAsync(buf, cts.Token);
        CollectionAssert.AreEqual(banner, buf);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_Accepts2xxResponse()
    {
        // RFC 9110: any 2xx response to CONNECT indicates success, not just 200
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var proxyEndPoint = (IPEndPoint)listener.LocalEndpoint;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var stubProxyTask = Task.Run(async () =>
        {
            // ReSharper disable once AccessToDisposedClosure
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            var stream = accepted.GetStream();

            // read request headers until CRLFCRLF
            var bytes = new List<byte>();
            var one = new byte[1];
            while (true)
            {
                var n = await stream.ReadAsync(one, cts.Token);
                if (n == 0) return;
                bytes.Add(one[0]);
                if (bytes.Count >= 4 &&
                    bytes[^4] == '\r' && bytes[^3] == '\n' &&
                    bytes[^2] == '\r' && bytes[^1] == '\n')
                    break;
            }

            await stream.WriteAsync("HTTP/1.1 202 Accepted\r\n\r\n"u8.ToArray(), cts.Token);

            // echo tunneled data afterwards
            var buf = new byte[1024];
            while (true)
            {
                var n = await stream.ReadAsync(buf, cts.Token);
                if (n <= 0) break;
                await stream.WriteAsync(buf.AsMemory(0, n), cts.Token);
            }
        }, cts.Token);

        try
        {
            var client = new HttpProxyClient(new HttpProxyClientOptions { ProxyEndPoint = proxyEndPoint });
            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, "example.com", 443, cts.Token);

            var stream = tcp.GetStream();
            var payload = "abc"u8.ToArray();
            await stream.WriteAsync(payload, cts.Token);
            var echoed = new byte[payload.Length];
            await stream.ReadExactlyAsync(echoed, cts.Token);
            CollectionAssert.AreEqual(payload, echoed);
        }
        finally
        {
            listener.Stop();
            try { await stubProxyTask; } catch { /* listener stopped */ }
        }
    }
}
