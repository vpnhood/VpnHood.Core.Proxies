using System.Buffers;
using System.Net.Security;
using System.Net.Sockets;

namespace VpnHood.Core.Proxies;

internal static class ProxyStreamPump
{
    private const int BufferSize = 4096;

    /// <summary>
    /// Pumps data between the two streams in both directions.
    ///
    /// Half-close policy: when one direction reaches EOF, the FIN is propagated to the peer
    /// that direction was writing to (TCP half-close), and the opposite direction is given
    /// <paramref name="halfCloseTimeout"/> to finish. Blindly cancelling both directions on the
    /// first EOF would break protocols that rely on half-close (e.g. an HTTP client that
    /// shuts down its send side and then reads the full response). Waiting forever would let
    /// one idle peer retain the whole tunnel (buffers, sockets, tasks, handler state) — fatal
    /// under tight memory limits such as an iOS Network Extension.
    /// </summary>
    /// <param name="clientStream">Stream to/from the proxy client.</param>
    /// <param name="remoteStream">Stream to/from the destination host.</param>
    /// <param name="halfCloseTimeout">How long the surviving direction may keep draining after
    /// the first direction reaches EOF.</param>
    /// <param name="cancellationToken">Cancels both directions and tears the tunnel down.</param>
    /// <param name="clientSocket">Socket behind <paramref name="clientStream"/>; only needed when the
    /// stream does not expose it itself (e.g. SslStream). Derived automatically for NetworkStream.</param>
    /// <param name="remoteSocket">Same for <paramref name="remoteStream"/>.</param>
    /// <param name="clientPrefix">Bytes already consumed from the client during the handshake
    /// (pipelined tunnel data or a request body start); written to the remote before pumping.</param>
    public static async Task PumpStreamsAsync(
        Stream clientStream,
        Stream remoteStream,
        TimeSpan halfCloseTimeout,
        CancellationToken cancellationToken,
        Socket? clientSocket = null,
        Socket? remoteSocket = null,
        ReadOnlyMemory<byte> clientPrefix = default)
    {
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var clientToRemote = CopyStreamAsync(clientStream, remoteStream, clientPrefix, pumpCts.Token);
        var remoteToClient = CopyStreamAsync(remoteStream, clientStream, ReadOnlyMemory<byte>.Empty, pumpCts.Token);

        try
        {
            var finished = await Task.WhenAny(clientToRemote, remoteToClient).ConfigureAwait(false);

            // Propagate the EOF to the stream the finished direction was writing to. Writes to
            // that stream only ever came from the finished copy, so shutting down its send side
            // here cannot race with an in-flight write.
            var (drainedStream, drainedSocket) = finished == clientToRemote
                ? (remoteStream, remoteSocket)
                : (clientStream, clientSocket);
            await TryShutdownSendAsync(drainedStream, drainedSocket).ConfigureAwait(false);

            // Give the remaining direction a bounded time to drain, then tear down.
            var remaining = finished == clientToRemote ? remoteToClient : clientToRemote;
            try
            {
                await remaining.WaitAsync(halfCloseTimeout, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // idle peer after half-close (timeout), stream error, or server shutdown —
                // in every case the tunnel is torn down below; the pump itself never throws
            }
        }
        finally
        {
            await pumpCts.CancelAsync().ConfigureAwait(false);
            foreach (var task in new[] { clientToRemote, remoteToClient })
            {
                try { await task.ConfigureAwait(false); }
                catch { /* Ignore exceptions during cleanup */ }
            }
        }
    }

    private static async Task TryShutdownSendAsync(Stream stream, Socket? socket)
    {
        // For TLS, send close_notify first so the peer's TLS layer sees a clean end of
        // stream instead of a truncation error
        try
        {
            if (stream is SslStream sslStream)
                await sslStream.ShutdownAsync().ConfigureAwait(false);
        }
        catch
        {
            // the connection may already be gone; the socket shutdown below still applies
        }

        try
        {
            socket ??= (stream as NetworkStream)?.Socket;
            socket?.Shutdown(SocketShutdown.Send);
        }
        catch
        {
            // already closed/reset by the peer
        }
    }

    private static async Task CopyStreamAsync(Stream sourceStream, Stream destinationStream,
        ReadOnlyMemory<byte> prefix, CancellationToken cancellationToken)
    {
        // Pooled: tunnels are the dominant per-connection cost, and returning the buffer in the
        // finally is safe because no read/write can still be in flight once the awaits complete.
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            if (!prefix.IsEmpty)
            {
                await destinationStream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
                await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            while (!cancellationToken.IsCancellationRequested)
            {
                var bytesRead = await sourceStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0) break;

                await destinationStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);

                // no-op for NetworkStream but required for SslStream
                await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch when (cancellationToken.IsCancellationRequested)
        {
            // Expected during cancellation
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
