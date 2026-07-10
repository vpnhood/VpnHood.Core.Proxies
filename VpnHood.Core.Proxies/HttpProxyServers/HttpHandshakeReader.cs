using System.Buffers;
using System.Net;
using System.Text;

namespace VpnHood.Core.Proxies.HttpProxyServers;

/// <summary>
/// Buffered line reader for HTTP handshakes. Reads from the stream in chunks (instead of one
/// syscall per byte) while never losing bytes that follow the header block: whatever was read
/// past the final CRLF (a request body start or pipelined tunnel data) is handed back via
/// <see cref="DetachRemainder"/> so the tunnel phase can forward it.
///
/// Hard limits: 8 KB per line, 100 headers, 32 KB total — a hostile client must not be able to
/// make one pending handshake allocate megabytes (many concurrent handshakes are cheap to open).
/// </summary>
internal sealed class HttpHandshakeReader(Stream stream) : IDisposable
{
    public const int MaxLineLength = 8192;
    public const int MaxTotalHeaderBytes = 32 * 1024;
    public const int MaxHeaderCount = 100;

    // one pooled buffer per handshake; a line must fit in it (MaxLineLength + CRLF slack)
    private byte[]? _buffer = ArrayPool<byte>.Shared.Rent(MaxLineLength + 1024);
    private int _start; // first unconsumed byte
    private int _end;   // one past the last valid byte
    private int _totalReadBytes;

    /// <summary>Returns the next line without CR/LF, or null on EOF before any byte was read.</summary>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        var buffer = _buffer ?? throw new ObjectDisposedException(nameof(HttpHandshakeReader));

        // bytes at the front of the window have already been scanned in a previous pass;
        // only new bytes are searched for the line end
        var scanned = 0;
        while (true)
        {
            var newlineIndex = Array.IndexOf(buffer, (byte)'\n', _start + scanned, _end - _start - scanned);
            if (newlineIndex >= 0)
            {
                var lineSpan = buffer.AsSpan(_start, newlineIndex - _start);
                if (lineSpan.Length > 0 && lineSpan[^1] == (byte)'\r')
                    lineSpan = lineSpan[..^1];
                if (lineSpan.Length > MaxLineLength)
                    throw new ProtocolViolationException("HTTP header line too long");

                // Latin-1: a 1:1 byte-to-char mapping, so malformed non-ASCII bytes cannot
                // corrupt the parse the way a multibyte decoder could
                var line = Encoding.Latin1.GetString(lineSpan);
                _start = newlineIndex + 1;
                return line;
            }

            scanned = _end - _start;
            if (scanned > MaxLineLength)
                throw new ProtocolViolationException("HTTP header line too long");

            // no line end in the buffer yet: compact the window to the front and refill
            if (_start > 0)
            {
                Buffer.BlockCopy(buffer, _start, buffer, 0, scanned);
                _end -= _start;
                _start = 0;
            }

            if (_end == buffer.Length)
                throw new ProtocolViolationException("HTTP header line too long");

            var read = await stream.ReadAsync(buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (_end == _start) return null;
                var rest = Encoding.Latin1.GetString(buffer.AsSpan(_start, _end - _start));
                _start = _end;
                return rest;
            }

            _end += read;
            _totalReadBytes += read;
            if (_totalReadBytes > MaxTotalHeaderBytes)
                throw new ProtocolViolationException("HTTP headers too large");
        }
    }

    public async Task<Dictionary<string, string>> ReadHeadersAsync(CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? line;
        while (!string.IsNullOrEmpty(line = await ReadLineAsync(cancellationToken).ConfigureAwait(false)))
        {
            if (headers.Count >= MaxHeaderCount)
                throw new ProtocolViolationException("Too many HTTP headers");

            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line[..colonIndex].Trim();
                var value = line[(colonIndex + 1)..].Trim();
                headers[name] = value;
            }
        }

        return headers;
    }

    /// <summary>
    /// Returns the bytes read past the header block and releases the pooled buffer immediately.
    /// The copy is deliberate: the remainder is usually empty, and copying the rare non-empty
    /// case is far cheaper than pinning a pooled 9 KB buffer for the whole tunnel lifetime.
    /// </summary>
    public byte[] DetachRemainder()
    {
        var buffer = _buffer ?? throw new ObjectDisposedException(nameof(HttpHandshakeReader));
        var remainder = _end > _start ? buffer.AsSpan(_start, _end - _start).ToArray() : [];
        Dispose();
        return remainder;
    }

    public void Dispose()
    {
        if (_buffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = null;
        }
    }
}
