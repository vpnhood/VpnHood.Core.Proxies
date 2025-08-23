# VpnHood Proxy Server and Client

This solution provides both server and client applications for testing HTTP, HTTPS, SOCKS4, and SOCKS5 proxy protocols.

## Projects

1. **VpnHood.Core.Proxies.ConsoleApp** - Proxy Server
2. **VpnHood.Core.Proxies.ClientApp** - Proxy Client

## Server Usage

### HTTP Proxy Server
```bash
dotnet run --project VpnHood.Core.Proxies.ServerApp -- http --host 127.0.0.1 --port 8080
dotnet run --project VpnHood.Core.Proxies.ServerApp -- http --port 8080 --username admin --password secret
```

### HTTPS Proxy Server
```bash
dotnet run --project VpnHood.Core.Proxies.ServerApp -- https --host 127.0.0.1 --port 8443
dotnet run --project VpnHood.Core.Proxies.ServerApp -- https --port 8443 --username admin --password secret
dotnet run --project VpnHood.Core.Proxies.ServerApp -- https --port 8443 --cert mycert.pfx
```

### SOCKS5 Proxy Server
```bash
dotnet run --project VpnHood.Core.Proxies.ServerApp -- socks5 --host 127.0.0.1 --port 1080
dotnet run --project VpnHood.Core.Proxies.ServerApp -- socks5 --port 1080 --username user --password pass
```

## Client Usage

### Test HTTP Proxy
```bash
dotnet run --project VpnHood.Core.Proxies.ClientApp -- http --proxy-port 8080
dotnet run --project VpnHood.Core.Proxies.ClientApp -- http --proxy-port 8080 --username admin --password secret
dotnet run --project VpnHood.Core.Proxies.ClientApp -- http --proxy-port 8080 --target-host google.com --target-port 80
```

### Test HTTPS Proxy
```bash
dotnet run --project VpnHood.Core.Proxies.ClientApp -- https --proxy-port 8443 --allow-invalid-cert
dotnet run --project VpnHood.Core.Proxies.ClientApp -- https --proxy-port 8443 --username admin --password secret --allow-invalid-cert
```

### Test SOCKS4 Proxy
```bash
dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks4 --proxy-port 1080
dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks4 --proxy-port 1080 --username user
```

### Test SOCKS5 Proxy
```bash
dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks5 --proxy-port 1080
dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks5 --proxy-port 1080 --username user --password pass
```

## Example Workflow

1. Start an HTTP proxy server with authentication:
   ```bash
   dotnet run --project VpnHood.Core.Proxies.ServerApp -- http --port 8080 --username admin --password secret
   ```

2. In another terminal, test the proxy:
   ```bash
   dotnet run --project VpnHood.Core.Proxies.ClientApp -- http --proxy-port 8080 --username admin --password secret
   ```

3. Start a SOCKS5 proxy server:
   ```bash
   dotnet run --project VpnHood.Core.Proxies.ServerApp -- socks5 --port 1080 --username user --password pass
   ```

4. Test the SOCKS5 proxy:
   ```bash
   dotnet run --project VpnHood.Core.Proxies.ClientApp -- socks5 --proxy-port 1080 --username user --password pass
   ```

## Features

### Server Features
- HTTP proxy with Basic authentication
- HTTPS proxy with SSL/TLS support and self-signed certificate generation
- SOCKS5 proxy with username/password authentication
- Configurable host and port bindings
- Graceful shutdown on Ctrl+C

### Client Features
- HTTP proxy client with authentication
- HTTPS proxy client with SSL certificate validation options
- SOCKS4 proxy client with user ID support
- SOCKS5 proxy client with authentication
- Customizable target host/port and data payload
- HTTP response parsing and display

### Authentication Support
- HTTP/HTTPS: Basic authentication (RFC 7617)
- SOCKS5: Username/password authentication (RFC 1929)
- SOCKS4: User ID field support

All proxy servers and clients support the authentication mechanisms specified in their respective RFCs.