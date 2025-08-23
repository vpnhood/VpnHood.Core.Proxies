using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VpnHood.Core.Proxies.Socks5ProxyClients;
using VpnHood.Core.Proxies.Socks5ProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class Socks5ProxyClientTests
{
    private static IPEndPoint StartSocks5Proxy(out CancellationTokenSource cts, string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new Socks5ProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new Socks5ProxyServer(serverOptions);
        cts = new CancellationTokenSource();
        _ = server.RunAsync(cts.Token);
        // Let it start and fetch the bound endpoint via reflection
        Thread.Sleep(50);
        var ep = (IPEndPoint)((TcpListener)typeof(Socks5ProxyServer)
            .GetField("_listener", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(server)!).LocalEndpoint;
        return ep;
    }

    [TestMethod]
    public async Task Socks5_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var proxyEp = StartSocks5Proxy(out var cts, user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = System.Text.Encoding.UTF8.GetBytes("hello socks5");
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);
        CollectionAssert.AreEqual(payload, buf);
        cts.Cancel();
    }

    [TestMethod]
    public async Task Socks5_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var proxyEp = StartSocks5Proxy(out var cts, user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        });
        cts.Cancel();
    }
}
