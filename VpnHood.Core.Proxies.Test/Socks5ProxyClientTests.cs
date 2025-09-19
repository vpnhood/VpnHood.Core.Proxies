using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;
using VpnHood.Core.Proxies.Socks5ProxyServers;
using VpnHood.Core.Proxies.Test.TestHelpers;
using IPEndPoint = System.Net.IPEndPoint;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class Socks5ProxyClientTests
{
    private static Task<Socks5ProxyServer> StartSocks5ProxyAsync(string? user = null, string? pass = null)
    {
        var listenEp = new IPEndPoint(IPAddress.Loopback, 0);
        var serverOptions = new Socks5ProxyServerOptions { ListenEndPoint = listenEp, Username = user, Password = pass };
        var server = new Socks5ProxyServer(serverOptions);
        server.Start();
        return Task.FromResult(server);
    }

    [TestMethod]
    public async Task Socks5_Connect_WithAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
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

    [TestMethod]
    public async Task Socks5_Connect_WithoutAuth_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_Connect_NoAuth_Succeeds()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
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

    [TestMethod]
    public async Task Socks5_Connect_WrongCredentials_Fails()
    {
        using var echo = new EchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "wrong", Password = "credentials" };
        var client = new Socks5ProxyClient(options);

        using var tcp = new TcpClient();
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.ConnectAsync(tcp, echo.EndPoint, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "user", Password = "pass" };
        var client = new Socks5ProxyClient(options);

        // Create UDP client for sending/receiving data
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish TCP control connection and UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

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

    [TestMethod]
    public async Task Socks5_UdpAssociate_WithoutAuth_Fails()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(user: "user", pass: "pass");

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint }; // No credentials
        var client = new Socks5ProxyClient(options);

        using var controlTcp = new TcpClient();
        
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_NoAuth_Succeeds()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        // Create UDP client
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

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

    [TestMethod]
    public async Task Socks5_UdpAssociate_Simple_Test()
    {
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
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

    [TestMethod]
    public async Task UdpEchoServer_DirectTest()
    {
        using var echoServer = new UdpEchoServer(IPAddress.Loopback);
        using var testClient = new UdpClient();

        var testMessage = "Test UDP Echo"u8.ToArray();
        
        // Send test message to echo server
        await testClient.SendAsync(testMessage, echoServer.EndPoint);
        
        // Receive echoed response
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var response = await testClient.ReceiveAsync(cts.Token);
        
        // Verify echo
        CollectionAssert.AreEqual(testMessage, response.Buffer);
        Assert.AreEqual(echoServer.EndPoint, response.RemoteEndPoint);
    }

    [TestMethod]
    public async Task Socks5_UdpAssociate_SendPacket_Test()
    {
        using var udpEcho = new UdpEchoServer(IPAddress.Loopback);
        using var server = await StartSocks5ProxyAsync(); // No auth required

        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);

        // Create UDP client
        using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var clientUdpEndpoint = (IPEndPoint)udpClient.Client.LocalEndPoint!;

        // Establish UDP association
        using var controlTcp = new TcpClient();
        var proxyUdpEndpoint = await client.CreateUdpAssociateAsync(controlTcp, clientUdpEndpoint, CancellationToken.None);

        // Give some time for the UDP relay to be established
        await Task.Delay(100);

        // Create SOCKS5 UDP request to the echo server
        var testMessage = "Hello UDP test!"u8.ToArray();
        var requestBuffer = new byte[1024];
        var requestLength = Socks5ProxyClient.WriteUdpRequest(requestBuffer, udpEcho.EndPoint, testMessage);
        
        // Send UDP packet through proxy
        await udpClient.SendAsync(requestBuffer.AsMemory(0, requestLength).ToArray(), proxyUdpEndpoint);
        
        // Receive echoed response via proxy and validate
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var response = await udpClient.ReceiveAsync(timeoutCts.Token);
        var responseEndpoint = Socks5ProxyClient.ParseUdpResponse(response.Buffer, out var responsePayload);
        
        Assert.IsNotNull(responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Address, responseEndpoint.Address);
        Assert.AreEqual(udpEcho.EndPoint.Port, responseEndpoint.Port);
        CollectionAssert.AreEqual(testMessage, responsePayload.ToArray());
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_NoAuth_Succeeds()
    {
        using var server = await StartSocks5ProxyAsync();
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WithAuth_Succeeds()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "u", Password = "p" };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await client.CheckConnectionAsync(tcp, CancellationToken.None);
        Assert.IsTrue(tcp.Connected);
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WithoutAuth_Fails()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CheckConnectionAsync(tcp, CancellationToken.None);
        });
    }

    [TestMethod]
    public async Task Socks5_CheckConnection_WrongCredentials_Fails()
    {
        using var server = await StartSocks5ProxyAsync(user: "u", pass: "p");
        var options = new Socks5ProxyClientOptions { ProxyEndPoint = server.ListenerEndPoint, Username = "wrong", Password = "creds" };
        var client = new Socks5ProxyClient(options);
        using var tcp = new TcpClient();
        await Assert.ThrowsExceptionAsync<UnauthorizedAccessException>(async () =>
        {
            await client.CheckConnectionAsync(tcp, CancellationToken.None);
        });
    }
}
