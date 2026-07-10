# VpnHood.Core.Proxies

**Standard proxy clients and servers for .NET** — SOCKS5, SOCKS4/4a, HTTP, and HTTPS, in one small cross-platform library with no native dependencies, built on `async`/`await` and `Span<byte>`.

This is an **independent, general-purpose library**: it implements the standard proxy protocols (RFC 1928, RFC 1929, HTTP CONNECT) and has no dependency on any VPN product. Use it in any .NET application to add proxy support, embed a lightweight proxy server, bridge traffic between networks, or test proxy-aware software. It is maintained by the [VpnHood](https://github.com/vpnhood/vpnhood) team and battle-tested there in production, but it works entirely on its own.

## Feature matrix

| Protocol | Client | Server |
| --- | --- | --- |
| **SOCKS5** (RFC 1928) | TCP CONNECT, UDP ASSOCIATE, username/password auth (RFC 1929), remote DNS (domain addresses), IPv4 + IPv6 | TCP CONNECT, UDP ASSOCIATE with source validation, username/password auth, IPv4 + IPv6 |
| **SOCKS4 / 4a** | TCP CONNECT, user-id, host names via SOCKS4a | — |
| **HTTP proxy** | CONNECT tunnels, Basic auth, optional TLS to the proxy itself | CONNECT tunnels + plain `GET/POST …` forwarding, Basic auth |
| **HTTPS proxy** (TLS between client and proxy) | `HttpProxyClient` with `UseTls = true` | `HttpsProxyServer` with your `X509Certificate2` |

Common properties:

* Standalone and reusable — plain .NET, no VPN or VpnHood runtime required; the only dependency is `Microsoft.Extensions.Logging.Abstractions`
* Fully asynchronous, cancellation-aware I/O; no blocking calls
* Handshake and connect timeouts with sensible defaults ([options classes](VpnHood.Core.Proxies/Socks5ProxyServers/Socks5ProxyServerOptions.cs))
* Built for memory-constrained hosts (mobile network extensions, small containers): every per-connection resource is bounded — `MaxConnections` cap, capped header sizes, bounded UDP destination tables, and a TCP half-close linger timeout so idle peers cannot retain tunnels indefinitely
* Correct TCP half-close: a peer that shuts down its send side still receives the full response through the tunnel
* Low-allocation hot paths (`ArrayPool`, pooled tunnel buffers, spans)
* Optional `Microsoft.Extensions.Logging` integration — pass an `ILogger`, or nothing
* Privacy-friendly: SOCKS5 client sends host names to the proxy for **remote DNS resolution** (no local lookup or DNS leak)
* SOCKS5 UDP relay only accepts datagrams from the associated client and from destinations that client has contacted — third parties cannot inject packets into an association

## Installation

```bash
dotnet add package VpnHood.Core.Proxies
```

Or add the project to your solution and reference it directly.

## Quick start

### Run a SOCKS5 proxy server

```csharp
using System.Net;
using VpnHood.Core.Proxies.Socks5ProxyServers;

using var server = new Socks5ProxyServer(new Socks5ProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
    Username = null, // set both to require RFC 1929 authentication
    Password = null
});

// Either run until cancelled...
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
await server.RunAsync(cts.Token);

// ...or control the lifetime yourself:
// server.Start();  /* later */  server.Stop();
```

### Connect through a SOCKS5 proxy (TCP)

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;

var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
    ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
    Username = null,
    Password = null
});

using var tcp = new TcpClient();

// Host names are sent to the proxy as SOCKS5 domain addresses,
// so DNS is resolved remotely — no local DNS leak.
await client.ConnectAsync(tcp, "example.com", 80, CancellationToken.None);

var stream = tcp.GetStream(); // the tunnel — speak HTTP, TLS, or anything else
```

A single `Socks5ProxyClient` instance is reusable across many connections; the handshake is negotiated per connection.

### Send UDP through a SOCKS5 proxy (UDP ASSOCIATE)

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks5ProxyClients;

var client = new Socks5ProxyClient(new Socks5ProxyClientOptions {
    ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 1080)
});

// local UDP socket used to exchange datagrams with the proxy
using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
var localUdpEndPoint = (IPEndPoint)udp.Client.LocalEndPoint!;

// the TCP control connection must stay open for the lifetime of the association
using var controlTcp = new TcpClient();
var relayEndPoint = await client.CreateUdpAssociateAsync(controlTcp, localUdpEndPoint, CancellationToken.None);

// wrap a payload in a SOCKS5 UDP header and send it via the relay
var destination = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53); // e.g. a DNS query
var payload = BuildMyDnsQuery();
var buffer = new byte[3 + 1 + 16 + 2 + payload.Length];
var length = Socks5ProxyClient.WriteUdpRequest(buffer, destination, payload);
await udp.SendAsync(buffer.AsMemory(0, length).ToArray(), relayEndPoint);

// receive and unwrap the response
var result = await udp.ReceiveAsync();
var from = Socks5ProxyClient.ParseUdpResponse(result.Buffer, out var responsePayload);
```

### Run an HTTP proxy server

```csharp
using System.Net;
using VpnHood.Core.Proxies.HttpProxyServers;

using var server = new HttpProxyServer(new HttpProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 8080),
    Username = null, // set both to require Basic authentication
    Password = null
});
server.Start();
```

Handles `CONNECT` tunnels (HTTPS traffic, IPv6 authorities like `[::1]:443` included) and forwards plain absolute-URI requests (`GET http://… HTTP/1.1`) with the client's headers preserved.

### Run an HTTPS proxy server (TLS between client and proxy)

```csharp
using System.Net;
using VpnHood.Core.Proxies.HttpProxyServers;

using var server = new HttpsProxyServer(new HttpProxyServerOptions {
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 8443),
    ServerCertificate = myCertificate // X509Certificate2 with a private key
});
server.Start();
```

### Connect through an HTTP(S) proxy

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.HttpProxyClients;

var client = new HttpProxyClient(new HttpProxyClientOptions {
    ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 8443),
    Username = "user",            // optional Basic auth
    Password = "pass",
    UseTls = true,                // TLS between you and the proxy (HTTPS proxy)
    ProxyHost = "proxy.example",  // TLS SNI / certificate name (optional)
    AllowInvalidCertificates = false
});

using var tcp = new TcpClient();
await client.ConnectAsync(tcp, "example.com", 443, CancellationToken.None);

// With UseTls the tunnel runs inside the TLS session — always take the
// stream from the client rather than tcp.GetStream():
var stream = client.GetStream(tcp);
```

The client accepts any `2xx` CONNECT response and maps proxy errors (407, 429, 5xx, …) to a typed `ProxyClientException` with a meaningful `SocketError` code. Tunnels where the server speaks first (SMTP, SSH, …) work correctly — no bytes are lost after the handshake.

### Connect through a SOCKS4/4a proxy

```csharp
using System.Net;
using System.Net.Sockets;
using VpnHood.Core.Proxies.Socks4ProxyClients;

var client = new Socks4ProxyClient(new Socks4ProxyClientOptions {
    ProxyEndPoint = new IPEndPoint(IPAddress.Loopback, 1080),
    UserName = null // optional SOCKS4 user-id
});

using var tcp = new TcpClient();
await client.ConnectAsync(tcp, "example.com", 80, CancellationToken.None); // host names use SOCKS4a
```

## Command-line apps

The repo ships two small CLI utilities, handy for manual testing:

* **VpnHood.Core.Proxies.ServerApp** (`VhProxyServer`) — run an HTTP, HTTPS, or SOCKS5 proxy server, with optional auth and self-signed certificate generation.
* **VpnHood.Core.Proxies.ClientApp** (`VhProxyClient`) — connect through any supported proxy and exchange test data.

```bash
dotnet run --project VpnHood.Core.Proxies.ServerApp -- socks5 --port 1080 --username user --password pass
dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks5 --proxy-port 1080 --username user --password pass
```

See [USAGE.md](USAGE.md) for all commands and options.

## Error handling

Proxy-level failures throw `ProxyClientException`, which derives from `SocketException` and carries a mapped `SocketError` (e.g. `ConnectionRefused`, `HostUnreachable`, `AccessDenied`), so existing socket error handling keeps working. Authentication failures throw `UnauthorizedAccessException`; malformed peers throw `ProtocolViolationException`.

## Testing

Integration tests live in `VpnHood.Core.Proxies.Test` and run the real clients against the real servers over loopback — including UDP relays, TLS proxies, IPv6 CONNECT, pipelined requests, and injection attempts against the UDP relay:

```bash
dotnet test
```

## License

[LGPL-2.1](LICENSE) © OmegaHood LLC — an independent library maintained by the [VpnHood](https://github.com/vpnhood/vpnhood) team.
