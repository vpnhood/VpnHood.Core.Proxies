# VpnHood.Core.Proxies

Cross-platform proxy servers and clients for .NET:
- SOCKS5 (TCP CONNECT and UDP ASSOCIATE)
- SOCKS4 (client)
- HTTP proxy (plain)
- HTTPS proxy (CONNECT over TLS)

## Features
- SOCKS5 server with optional username/password auth
- SOCKS5 client with TCP CONNECT and UDP ASSOCIATE helpers
- HTTP and HTTPS proxy servers with optional Basic auth
- Sensible defaults for timeouts and backlog
- Cancellation-aware async I/O
- Low-allocation hot paths (MemoryPool, spans)

## Getting started
Add the VpnHood.Core.Proxies project to your solution

Samples and CLI utilities are available in the repo; see:
[CLI Usage](https://github.com/vpnhood/VpnHood.Core.Proxies/blob/main/USAGE.md)

## Usage snippets

- Start a SOCKS5 proxy server

```csharp
using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using VpnHood.Core.Proxies.Socks5ProxyServers;

var loggerFactory = LoggerFactory.Create(b => b.AddSimpleConsole(o => o.TimestampFormat = "HH:mm:ss ")); 
var logger = loggerFactory.CreateLogger<Socks5ProxyServer>();

var options = new Socks5ProxyServerOptions
{
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
    Username = null, // or "user"
    Password = null, // or "pass"
};

using var server = new Socks5ProxyServer(options, logger);
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
await server.RunAsync(cts.Token);
```

- Start an HTTP proxy server

```csharp
using System.Net;
using Microsoft.Extensions.Logging;
using VpnHood.Core.Proxies.HttpProxyServers;

var httpOptions = new HttpProxyServerOptions
{
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 8080),
    Username = null, // set to require Basic auth
    Password = null
};

using var http = new HttpProxyServer(httpOptions);
await http.RunAsync();
```

- Connect through SOCKS5 proxy (TCP CONNECT)

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;

var proxy = new IPEndPoint(IPAddress.Loopback, 1080);
var clientOptions = new Socks5ProxyClientOptions
{
    ProxyEndPoint = proxy,
    Username = null,
    Password = null
};

var socksClient = new Socks5ProxyClient(clientOptions);
using var tcp = new TcpClient();
await socksClient.ConnectAsync(tcp, "example.com", 80, CancellationToken.None);

// use tcp.GetStream() to speak HTTP or another protocol
```

- SOCKS5 UDP associate (send a UDP datagram via proxy)

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;

var proxy = new IPEndPoint(IPAddress.Loopback, 1080);
var clientOptions = new Socks5ProxyClientOptions { ProxyEndPoint = proxy };
var socksClient = new Socks5ProxyClient(clientOptions);

using var controlTcp = new TcpClient();
// Create UDP associate and get proxy UDP endpoint
var udpProxyEndpoint = await socksClient.CreateUdpAssociateAsync(controlTcp, CancellationToken.None);

// Prepare a UDP packet to the destination using the helper
var destination = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53); // example: DNS
Span<byte> payload = stackalloc byte[] { /* your UDP payload */ };
Span<byte> buffer = stackalloc byte[3 + 1 + 4 + 2 + 512]; // RSV/FRAG + ATYP + IPv4 + port + payload
var len = Socks5ProxyClient.WriteUdpRequest(buffer, destination, payload);

using var udp = new UdpClient();
await udp.SendAsync(buffer[..len].ToArray(), udpProxyEndpoint);
```

For complete runnable examples and CLI usage, see the sample apps linked above.

## Tests
Basic integration tests are under VpnHood.Core.Proxies.Test.
