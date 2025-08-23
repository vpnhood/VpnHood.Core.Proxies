using System.Net;

namespace VpnHood.Core.Proxies.Test.TestHelpers;

public sealed class ProxyServerTestInstance : IDisposable
{
    public required object Server { get; init; }
    public required IPEndPoint EndPoint { get; init; }
    public required CancellationTokenSource CancellationTokenSource { get; init; }

    public void Dispose()
    {
        try
        {
            CancellationTokenSource.Cancel();
        }
        catch
        {
            // Ignore cancellation errors
        }

        try
        {
            if (Server is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        catch
        {
            // Ignore disposal errors
        }

        try
        {
            CancellationTokenSource.Dispose();
        }
        catch
        {
            // Ignore disposal errors
        }
    }
}