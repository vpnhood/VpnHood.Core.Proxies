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
        await Task.Delay(50, cts.Token);
        
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
            var payload = "hello socks5"u8.ToArray();
            await stream.WriteAsync(payload);
            var buf = new byte[payload.Length];
            await stream.ReadExactlyAsync(buf);
            CollectionAssert.AreEqual(payload, buf);
        }
        finally
        {
            await cts.CancelAsync();
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
            await cts.CancelAsync();
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
            var payload = "hello socks5 no auth"u8.ToArray();
            await stream.WriteAsync(payload);
            var buf = new byte[payload.Length];
            await stream.ReadExactlyAsync(buf);
            CollectionAssert.AreEqual(payload, buf);
        }
        finally
        {
            await cts.CancelAsync();
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
            await cts.CancelAsync();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp, Username = "user", Password = "pass" };
            var client = new Socks5ProxyClient(options);

            // Create UDP client for sending/receiving data
            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

            // Establish TCP control connection and UDP association
            using var controlTcp = new TcpClient();
            var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

            // Prepare test data
            var testMessage = "Hello UDP through SOCKS5!"u8.ToArray();
            
            // Create SOCKS5 UDP request packet
            var requestBuffer = new byte[1024];
            var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
            var udpRequest = requestBuffer.AsMemory(0, requestLength);

            // Send UDP packet through proxy
            await udpClient.SendAsync(udpRequest.ToArray(), proxyUdpEndpoint);

            // Receive response through proxy
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var response = await udpClient.ReceiveAsync(timeoutCts.Token);

            // Parse SOCKS5 UDP response
            var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
            
            // Verify the response
            Assert.IsNotNull(responseEndpoint.Address);
            Assert.AreEqual(udpEcho.EndPoint.Address, responseEndpoint.Address);
            Assert.AreEqual(udpEcho.EndPoint.Port, responseEndpoint.Port);
            CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
        }
        finally
        {
            await cts.CancelAsync();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithoutAuth_Fails()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp }; // No credentials
            var client = new Socks5ProxyClient(options);

            using var controlTcp = new TcpClient();
            
            await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
            {
                await client.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);
            });
        }
        finally
        {
            await cts.CancelAsync();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_NoAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(); // No auth required

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp };
            var client = new Socks5ProxyClient(options);

            // Create UDP client
            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

            // Establish UDP association
            using var controlTcp = new TcpClient();
            var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

            // Test UDP communication
            var testMessage = "Hello UDP no auth!"u8.ToArray();
            var requestBuffer = new byte[1024];
            var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
            
            await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);

            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var response = await udpClient.ReceiveAsync(timeoutCts.Token);

            var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
            
            Assert.IsNotNull(responseEndpoint.Address);
            CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
        }
        finally
        {
            await cts.CancelAsync();
            server.Dispose();
        }
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_Simple_Test()
    {
        var (server, proxyEp, cts) = await StartSocks5ProxyAsync(); // No auth required

        try
        {
            var options = new Socks5ProxyClientOptions { ProxyEndPoint = proxyEp };
            var client = new Socks5ProxyClient(options);

            // Just test the UDP ASSOCIATE command without actual UDP traffic
            using var controlTcp = new TcpClient();
            var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);
            
            // Verify we got a valid UDP endpoint from the proxy
            Assert.IsNotNull(proxyUdpEndpoint);
            Assert.IsTrue(proxyUdpEndpoint.Port > 0);
            
            // The control connection should remain open
            Assert.IsTrue(controlTcp.Connected);
        }
        finally
        {
            await cts.CancelAsync();
            server.Dispose();
        }
    }
}
