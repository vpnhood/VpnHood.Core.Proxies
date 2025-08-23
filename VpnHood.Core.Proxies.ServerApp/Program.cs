using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VpnHood.Core.Proxies.HttpProxyServers;
using VpnHood.Core.Proxies.Socks5ProxyServers;

namespace VpnHood.Core.Proxies.ConsoleApp;

internal class Program
{
    static async Task<int> Main(string[] args)
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
                    await RunHttpProxy(options);
                    break;
                case "https":
                    await RunHttpsProxy(options);
                    break;
                case "socks5":
                    await RunSocks5Proxy(options);
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

    static void ShowHelp()
    {
        Console.WriteLine("VpnHood Proxy Server - supports HTTP, HTTPS, and SOCKS5 proxy protocols");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  ProxyServer <command> [options]");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  http      Start HTTP proxy server");
        Console.WriteLine("  https     Start HTTPS proxy server");
        Console.WriteLine("  socks5    Start SOCKS5 proxy server");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --host <host>        Host to bind to (default: 127.0.0.1)");
        Console.WriteLine("  --port <port>        Port to listen on (default: http=8080, https=8443, socks5=1080)");
        Console.WriteLine("  --username <user>    Username for authentication");
        Console.WriteLine("  --password <pass>    Password for authentication");
        Console.WriteLine("  --cert <path>        Path to certificate file (.pfx) for HTTPS");
        Console.WriteLine();
        Console.WriteLine("Examples:");
        Console.WriteLine("  ProxyServer http --port 8080");
        Console.WriteLine("  ProxyServer https --port 8443 --username admin --password secret");
        Console.WriteLine("  ProxyServer socks5 --port 1080 --username user --password pass");
    }

    static Dictionary<string, string> ParseArgs(string[] args)
    {
        var options = new Dictionary<string, string>();
        for (int i = 0; i < args.Length; i += 2)
        {
            if (i + 1 < args.Length && args[i].StartsWith("--"))
            {
                options[args[i][2..]] = args[i + 1];
            }
        }
        return options;
    }

    static async Task RunHttpProxy(Dictionary<string, string> options)
    {
        var host = options.GetValueOrDefault("host", "127.0.0.1");
        var port = int.Parse(options.GetValueOrDefault("port", "8080"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");

        var listenEp = new IPEndPoint(IPAddress.Parse(host), port);
        var serverOptions = new HttpProxyServerOptions
        {
            ListenEndPoint = listenEp,
            Username = username,
            Password = password
        };

        var server = new HttpProxyServer(serverOptions);
        Console.WriteLine($"Starting HTTP proxy server on {host}:{port}");
        if (username != null)
            Console.WriteLine($"Authentication required: {username}");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            await server.RunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Server stopped.");
        }
    }

    static async Task RunHttpsProxy(Dictionary<string, string> options)
    {
        var host = options.GetValueOrDefault("host", "127.0.0.1");
        var port = int.Parse(options.GetValueOrDefault("port", "8443"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");
        var certPath = options.GetValueOrDefault("cert");

        X509Certificate2 cert;
        if (certPath != null && File.Exists(certPath))
        {
            cert = new X509Certificate2(certPath);
            Console.WriteLine($"Using certificate from: {certPath}");
        }
        else
        {
            cert = CreateSelfSignedCertificate(host);
            Console.WriteLine("Using self-signed certificate (clients may show warnings)");
        }

        var listenEp = new IPEndPoint(IPAddress.Parse(host), port);
        var serverOptions = new HttpProxyServerOptions
        {
            ListenEndPoint = listenEp,
            Username = username,
            Password = password,
            ServerCertificate = cert
        };

        var server = new HttpsProxyServer(serverOptions);
        Console.WriteLine($"Starting HTTPS proxy server on {host}:{port}");
        if (username != null)
            Console.WriteLine($"Authentication required: {username}");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            await server.RunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Server stopped.");
        }
        finally
        {
            cert.Dispose();
        }
    }

    static async Task RunSocks5Proxy(Dictionary<string, string> options)
    {
        var host = options.GetValueOrDefault("host", "127.0.0.1");
        var port = int.Parse(options.GetValueOrDefault("port", "1080"));
        var username = options.GetValueOrDefault("username");
        var password = options.GetValueOrDefault("password");

        var listenEp = new IPEndPoint(IPAddress.Parse(host), port);
        var serverOptions = new Socks5ProxyServerOptions
        {
            ListenEndPoint = listenEp,
            Username = username,
            Password = password
        };

        var server = new Socks5ProxyServer(serverOptions);
        Console.WriteLine($"Starting SOCKS5 proxy server on {host}:{port}");
        if (username != null)
            Console.WriteLine($"Authentication required: {username}");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            await server.RunAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Server stopped.");
        }
    }

    static X509Certificate2 CreateSelfSignedCertificate(string hostname)
    {
        using var ecdsa = ECDsa.Create();
        var req = new CertificateRequest($"CN={hostname}", ecdsa, HashAlgorithmName.SHA256);
        
        // Add Subject Alternative Name
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostname);
        if (IPAddress.TryParse(hostname, out var ip))
            sanBuilder.AddIpAddress(ip);
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        req.CertificateExtensions.Add(sanBuilder.Build());

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert;
    }
}
