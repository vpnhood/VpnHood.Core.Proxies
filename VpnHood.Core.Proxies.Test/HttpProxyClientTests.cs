using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.HttpProxyClients;
using VpnHood.Core.Proxies.HttpProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class HttpProxyClientTests
{
    private static async Task<(HttpProxyServer server, IPEndPoint endpoint, CancellationTokenSource cts)> StartHttpProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new HttpProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new HttpProxyServer(serverOptions);
        var cts = new CancellationTokenSource();
        
        // Start the server
        server.Start();
        
        // Get the actual bound endpoint
        var listenerField = typeof(HttpProxyServer).GetField("_listener", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var listener = (TcpListener)listenerField!.GetValue(server)!;
        var actualEndpoint = (IPEndPoint)listener.LocalEndpoint;
        
        // Start the server loop in background
        _ = server.RunAsync(cts.Token);
        
        // Give server time to start accepting connections
        await Task.Delay(50);
        
        return (server, actualEndpoint, cts);
    }

    [TestMethod]
    public async Task HttpProxy_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartHttpProxyAsync(user: "u", pass: "p");

        try
        {
            var clientOptions = new HttpProxyOptions
            {
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
            var payload = System.Text.Encoding.UTF8.GetBytes("hello");
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
    public async Task HttpProxy_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartHttpProxyAsync(user: "u", pass: "p");

        try
        {
            var clientOptions = new HttpProxyOptions
            {
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
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task HttpProxy_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartHttpProxyAsync(); // No auth required

        try
        {
            var clientOptions = new HttpProxyOptions
            {
                ProxyEndPoint = proxyEp,
                UseTls = false,
                AllowInvalidCertificates = true
            };
            var client = new HttpProxyClient(clientOptions);
            using var tcp = new TcpClient();
            await client.ConnectAsync(tcp, echo.EndPoint.Address.ToString(), echo.EndPoint.Port, CancellationToken.None);

            var stream = tcp.GetStream();
            var payload = System.Text.Encoding.UTF8.GetBytes("hello no auth");
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
    public async Task HttpProxy_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartHttpProxyAsync(user: "u", pass: "p");

        try
        {
            var clientOptions = new HttpProxyOptions
            {
                ProxyEndPoint = proxyEp,
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
        finally
        {
            cts.Cancel();
            server.Dispose();
        }
    }
}
