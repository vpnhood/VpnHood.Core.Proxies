namespace VpnHood.Core.Proxies.HttpProxyServers;

public readonly struct HttpHandshakeResult
{
    public string Method { get; init; }
    public string Target { get; init; }
    public Dictionary<string, string> Headers { get; init; }

    /// <summary>
    /// Bytes received after the header block (start of a request body or pipelined tunnel
    /// data). They were unavoidably consumed while reading the headers and must be forwarded
    /// to the destination before any further client bytes.
    /// </summary>
    public byte[] Remainder { get; init; }

    public bool IsValid { get; init; }

    public static HttpHandshakeResult Invalid => new() { IsValid = false, Remainder = [] };

    public static HttpHandshakeResult Valid(string method, string target, Dictionary<string, string> headers, byte[] remainder)
    {
        return new HttpHandshakeResult
        {
            Method = method,
            Target = target,
            Headers = headers,
            Remainder = remainder,
            IsValid = true
        };
    }
}
