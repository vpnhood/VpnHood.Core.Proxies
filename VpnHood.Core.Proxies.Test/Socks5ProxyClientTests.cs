using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;
using VpnHood.Core.Proxies.Socks5ProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class Socks5ProxyClientTests
{
    private static async Task<(Socks5ProxyServer server, IPEndPoint endpoint, CancellationTokenSource cts)> StartSocks5ProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new Socks5ProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new Socks5ProxyServer(serverOptions);
        var cts = new CancellationTokenSource();
        
        // Start the server
        server.Start();
        
        // Get the actual bound endpoint
        var listenerField = typeof(Socks5ProxyServer).GetField("_listener", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var listener = (TcpListener)listenerField!.GetValue(server)!;
        var actualEndpoint = (IPEndPoint)listener.LocalEndpoint;
        
        // Start the server loop in background
        _ = server.RunAsync(cts.Token);
        
        // Give server time to start accepting connections
        await Task.Delay(50);
        
        return (server, actualEndpoint, cts);
    }

    [TestMethod]
    public async Task Socks5_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        try
        {
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
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp };
            var client = new Socks5ProxyClient(options);

            using var tcp = new TcpClient();
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
            {
                await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
            });
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(); // No auth required

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp };
            var client = new Socks5ProxyClient(options);

            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);

            var stream = tcp.GetStream();
            var payload = System.Text.Encoding.UTF8.GetBytes("hello socks5 no auth");
            await stream.WriteAsync(payload);
            var buf = new byte[payload.Length];
            await stream.ReadExactlyAsync(buf);
            CollectionAssert.AreEqual(payload, buf);
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp, Username = "wrong", Password = "credentials" };
            var client = new Socks5ProxyClient(options);

            using var tcp = new TcpClient();
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
            {
                await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
            });
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }
}
