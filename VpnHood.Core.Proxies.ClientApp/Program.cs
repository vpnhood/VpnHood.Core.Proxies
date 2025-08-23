using System.Net;
using System.Net.Sockets;
using System.Text;
using VpnHood.Core.Proxies.HttpProxyClients;
using VpnHood.Core.Proxies.Socks4ProxyClients;
using VpnHood.Core.Proxies.Socks5ProxyClients;

namespace VpnHood.Core.Proxies.ClientApp;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            ShowHelp();
            return 1;
        }

        var command = args[0].ToLower();
        var options = ParseArgs(args.Skip(1).ToArray());

        try
        {
            switch (command)
            {
                case "http":
                    await TestHttpProxy(options);
                    break;
                case "https":
                    await TestHttpsProxy(options);
                    break;
                case "socks4":
                    await TestSocks4Proxy(options);
                    break;
                case "socks5":
                    await TestSocks5Proxy(options);
                    break;
                default:
                    Console.WriteLine($"Unknown command: {command}");
                    ShowHelp();
                    return 1;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static void ShowHelp()
    {
        Console.WriteLine("VpnHood Proxy Client - test connections through HTTP, HTTPS, SOCKS4, and SOCKS5 proxies");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  ProxyClient <command> [options]");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  http      Connect through HTTP proxy");
        Console.WriteLine("  https     Connect through HTTPS proxy");
        Console.WriteLine("  socks4    Connect through SOCKS4 proxy");
        Console.WriteLine("  socks5    Connect through SOCKS5 proxy");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --proxy-host <host>    Proxy server host (default: 127.0.0.1)");
        Console.WriteLine("  --proxy-port <port>    Proxy server port (default: http=8080, https=8443, socks=1080)");
        Console.WriteLine("  --target-host <host>   Target host to connect to (default: httpbin.org)");
        Console.WriteLine("  --target-port <port>   Target port to connect to (default: 80)");
        Console.WriteLine("  --username <user>      Username for proxy authentication");
        Console.WriteLine("  --password <pass>      Password for proxy authentication");
        Console.WriteLine("  --data <data>          Data to send to target server");
        Console.WriteLine("  --allow-invalid-cert   Allow invalid SSL certificates (HTTPS only)");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  VhProxyClient http --proxy-port 8080");
        Console.WriteLine("  VhProxyClient https --proxy-port 8443 --username admin --password secret");
        Console.WriteLine("  VhProxyClient socks5 --proxy-port 1080 --target-host google.com --target-port 80");
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var options = new Dictionary<string, string>();
        for (int i = 0; i < args.Length; i += 2)
        {
            if (i + 1 < args.Length && args[i].StartsWith("--"))
            {
                options[args[i][2..]] = args[i + 1];
            }
            else if (args[i].StartsWith("--") && args[i] == "--allow-invalid-cert")
            {
                options[args[i][2..]] = "true";
                i--; // Don't skip next arg
            }
        }
        return options;
    }

    private static async Task TestHttpProxy(Dictionary<string, string> options)
    {
        var proxyHost = options.GetValueOrDefault("proxy-host", "127.0.0.1");
        var proxyPort = int.Parse(options.GetValueOrDefault("proxy-port", "8080"));
        var targetHost = options.GetValueOrDefault("target-host", "httpbin.org");
        var targetPort = int.Parse(options.GetValueOrDefault("target-port", "80"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");
        var data = options.GetValueOrDefault("data", "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

        var proxyEp = new IPEndPoint(IPAddress.Parse(proxyHost), proxyPort);
        var clientOptions = new HttpProxyOptions
        {
            ProxyEndPoint = proxyEp,
            Username = username,
            Password = password,
            UseTls = false,
            AllowInvalidCertificates = true
        };

        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        Console.WriteLine($"Connecting to {targetHost}:{targetPort} through HTTP proxy {proxyHost}:{proxyPort}...");
        await client.ConnectAsync(tcp, targetHost, targetPort, CancellationToken.None);
        Console.WriteLine("Connected successfully!");

        await SendAndReceiveData(tcp, targetHost, data);
    }

    private static async Task TestHttpsProxy(Dictionary<string, string> options)
    {
        var proxyHost = options.GetValueOrDefault("proxy-host", "127.0.0.1");
        var proxyPort = int.Parse(options.GetValueOrDefault("proxy-port", "8443"));
        var targetHost = options.GetValueOrDefault("target-host", "httpbin.org");
        var targetPort = int.Parse(options.GetValueOrDefault("target-port", "80"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");
        var data = options.GetValueOrDefault("data", "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        var allowInvalidCert = options.ContainsKey("allow-invalid-cert");

        var proxyEp = new IPEndPoint(IPAddress.Parse(proxyHost), proxyPort);
        var clientOptions = new HttpProxyOptions
        {
            ProxyEndPoint = proxyEp,
            ProxyHost = proxyHost,
            Username = username,
            Password = password,
            UseTls = true,
            AllowInvalidCertificates = allowInvalidCert
        };

        var client = new HttpProxyClient(clientOptions);
        using var tcp = new TcpClient();

        Console.WriteLine($"Connecting to {targetHost}:{targetPort} through HTTPS proxy {proxyHost}:{proxyPort}...");
        await client.ConnectAsync(tcp, targetHost, targetPort, CancellationToken.None);
        Console.WriteLine("Connected successfully!");

        await SendAndReceiveData(tcp, targetHost, data);
    }

    private static async Task TestSocks4Proxy(Dictionary<string, string> options)
    {
        var proxyHost = options.GetValueOrDefault("proxy-host", "127.0.0.1");
        var proxyPort = int.Parse(options.GetValueOrDefault("proxy-port", "1080"));
        var targetHost = options.GetValueOrDefault("target-host", "httpbin.org");
        var targetPort = int.Parse(options.GetValueOrDefault("target-port", "80"));
        var username = options.GetValueOrDefault("username");
        var data = options.GetValueOrDefault("data", "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

        var proxyEp = new IPEndPoint(IPAddress.Parse(proxyHost), proxyPort);
        var clientOptions = new Socks4ProxyClientOptions
        {
            ProxyEndPoint = proxyEp,
            UserName = username
        };

        var client = new Socks4ProxyClient(clientOptions);
        using var tcp = new TcpClient();

        Console.WriteLine($"Connecting to {targetHost}:{targetPort} through SOCKS4 proxy {proxyHost}:{proxyPort}...");
        await client.ConnectAsync(tcp, targetHost, targetPort, CancellationToken.None);
        Console.WriteLine("Connected successfully!");

        await SendAndReceiveData(tcp, targetHost, data);
    }

    private static async Task TestSocks5Proxy(Dictionary<string, string> options)
    {
        var proxyHost = options.GetValueOrDefault("proxy-host", "127.0.0.1");
        var proxyPort = int.Parse(options.GetValueOrDefault("proxy-port", "1080"));
        var targetHost = options.GetValueOrDefault("target-host", "httpbin.org");
        var targetPort = int.Parse(options.GetValueOrDefault("target-port", "80"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");
        var data = options.GetValueOrDefault("data", "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

        var proxyEp = new IPEndPoint(IPAddress.Parse(proxyHost), proxyPort);
        var clientOptions = new Socks5ProxyClientOptions
        {
            ProxyEndPoint = proxyEp,
            Username = username,
            Password = password
        };

        var client = new Socks5ProxyClient(clientOptions);
        using var tcp = new TcpClient();

        Console.WriteLine($"Connecting to {targetHost}:{targetPort} through SOCKS5 proxy {proxyHost}:{proxyPort}...");
        await client.ConnectAsync(tcp, targetHost, targetPort, CancellationToken.None);
        Console.WriteLine("Connected successfully!");

        await SendAndReceiveData(tcp, targetHost, data);
    }

    private static async Task SendAndReceiveData(TcpClient tcp, string targetHost, string data)
    {
        var stream = tcp.GetStream();
        
        // Replace {host} placeholder
        var finalData = data.Replace("{host}", targetHost);
        
        Console.WriteLine($"Sending data: {finalData.Replace("\r\n", @"\r\n")}");
        var sendBytes = Encoding.UTF8.GetBytes(finalData);
        await stream.WriteAsync(sendBytes);
        await stream.FlushAsync();

        // Read response
        var buffer = new byte[4096];
        var received = new StringBuilder();
        var totalBytes = 0;

        try
        {
            // Set a timeout for reading response
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            
            while (totalBytes < buffer.Length - 1)
            {
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(totalBytes), cts.Token);
                if (bytesRead == 0) break;
                
                var chunk = Encoding.UTF8.GetString(buffer, totalBytes, bytesRead);
                received.Append(chunk);
                totalBytes += bytesRead;

                // Check if we have a complete HTTP response
                var response = received.ToString();
                if (response.Contains("\r\n\r\n"))
                {
                    // If we have content-length, try to read the body
                    if (response.Contains("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    {
                        var lines = response.Split('\n');
                        foreach (var line in lines)
                        {
                            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                            {
                                if (int.TryParse(line.Split(':')[1].Trim(), out var contentLength))
                                {
                                    var headerEnd = response.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
                                    var bodyLength = response.Length - headerEnd;
                                    if (bodyLength >= contentLength) goto done;
                                }
                                break;
                            }
                        }
                    }
                    else if (response.Contains("Connection: close", StringComparison.OrdinalIgnoreCase))
                    {
                        // Server will close connection when done
                    }
                    else
                    {
                        // No content-length and no connection close, assume we have everything
                        break;
                    }
                }
            }
            done:;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Response reading timed out");
        }

        Console.WriteLine($"\nReceived response ({totalBytes} bytes):");
        Console.WriteLine(received.ToString());
    }
}
