using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks4ProxyClients;

namespace VpnHood.Core.Proxies.Test;

[TestClass]
public class Socks4ProxyClientTests
{
    [TestMethod]
    public async Task Socks4_CheckConnection_Succeeds()
    {
        // SOCKS4 server implementation is not present; validate basic TCP connectivity to a listening socket.
        // Use a simple TcpListener to simulate a proxy endpoint for connection check only.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;

        try
        {
            var options = new Socks4ProxyClientOptions { ProxyEndPoint = endpoint };
            var client = new Socks4ProxyClient(options);
            using var tcp = new TcpClient();

            var acceptTask = listener.AcceptTcpClientAsync();
            await client.CheckConnectionAsync(tcp, CancellationToken.None);

            // Ensure server accepted a connection
            using var accepted = await acceptTask.ConfigureAwait(false);
            Assert.IsTrue(tcp.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }
}
