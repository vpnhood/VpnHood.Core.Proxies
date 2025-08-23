using System.Net.Sockets;

namespace VpnHood.Core.Proxies.HttpProxyServers;

public readonly struct HttpHandshakeResult
{
    public string Method { get; init; }
    public string Target { get; init; }
    public Dictionary<string, string> Headers { get; init; }
    public StreamReader Reader { get; init; }
    public StreamWriter Writer { get; init; }
    public bool IsValid { get; init; }

    public static HttpHandshakeResult Invalid => new() { IsValid = false };

    public static HttpHandshakeResult Valid(string method, string target, Dictionary<string, string> headers, StreamReader reader, StreamWriter writer)
    {
        return new HttpHandshakeResult
        {
            Method = method,
            Target = target,
            Headers = headers,
            Reader = reader,
            Writer = writer,
            IsValid = true
        };
    }
}