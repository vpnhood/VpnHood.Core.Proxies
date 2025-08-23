using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VpnHood.Core.Proxies.HttpProxyClients;
using VpnHood.Core.Proxies.HttpProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class HttpProxyClientTests
{
    [TestMethod]
    public async Task HttpProxy_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);

        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new HttpProxyServerOptions { ListenEndPoint = listenEp, Username = "u", Password = "p" };
        var server = new HttpProxyServer(serverOptions);
        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        await Task.Delay(50);
        var proxyEp = (IPEndPoint)((System.Net.Sockets.TcpListener)typeof(HttpProxyServer)
            .GetField("_listener", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(server)!).LocalEndpoint;

        var clientOptions = new HttpProxyOptions {
            ProxyEndPoint = proxyEp,
            Username = "u",
            Password = "p",
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();
        await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

        var stream = tcp.GetStream();
        var payload = System.Text.Encoding.ASCII.GetBytes("hello");
        await stream.WriteAsync(payload);
        var buf = new byte[payload.Length];
        await stream.ReadExactlyAsync(buf);

        CollectionAssert.AreEqual(payload, buf);
        cts.Cancel();
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new HttpProxyServerOptions { ListenEndPoint = listenEp, Username = "u", Password = "p" };
        var server = new HttpProxyServer(serverOptions);
        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        await Task.Delay(50);
        var proxyEp = (IPEndPoint)((System.Net.Sockets.TcpListener)typeof(HttpProxyServer)
            .GetField("_listener", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(server)!).LocalEndpoint;

        var clientOptions = new HttpProxyOptions {
            ProxyEndPoint = proxyEp,
            UseTls = false,
            AllowInvalidCertificates = true
        };
        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        await Assert.ThrowsExceptionAsync<HttpRequestException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);
        });
        cts.Cancel();
    }
}
