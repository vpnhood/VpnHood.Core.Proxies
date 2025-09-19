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

        await Assert.ThrowsExceptionAsync<HttpRequestException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);
        });
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

        await Assert.ThrowsExceptionAsync<HttpRequestException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);
        });
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
}
