using System.Net;
using System.Net.Sockets;

namespace VpnHood.Core.Proxies.Test.TestHelpers;

internal sealed class UdpEchoServer : IDisposable
{
    private readonly UdpClient _udpClient;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _echoTask;

    public IPEndPoint EndPoint { get; }

    public UdpEchoServer(IPAddress address)
    {
        _udpClient = new UdpClient(new IPEndPoint(address, 0));
        EndPoint = (IPEndPoint)_udpClient.Client.LocalEndPoint!;
        _echoTask = Task.Run(EchoLoopAsync);
    }

    private async Task EchoLoopAsync()
    {
        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                var result = await _udpClient.ReceiveAsync(_cts.Token);
                var remoteEndPoint = result.RemoteEndPoint;
                var data = result.Buffer;

                // Echo the data back to the sender
                await _udpClient.SendAsync(data, remoteEndPoint);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when cancellation is requested
        }
        catch (Exception)
        {
            // Log or handle other exceptions if needed
        }
    }

    public void Dispose()
    {
        try
        {
            _cts.Cancel();
            _echoTask.Wait(TimeSpan.FromSeconds(1));
        }
        catch
        {
            // Ignore cleanup exceptions
        }
        finally
        {
            _udpClient.Dispose();
            _cts.Dispose();
        }
    }
}