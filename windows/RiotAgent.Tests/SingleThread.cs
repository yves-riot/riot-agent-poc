using System.Collections.Concurrent;

namespace Riot.Agent.Tests;

/// <summary>Runs an async test on one thread, as the guard runs on the UI thread: continuations
/// come back to it in order, so the tests are deterministic.</summary>
public static class SingleThread
{
    public static void Run(Func<Task> test)
    {
        var previous = SynchronizationContext.Current;
        var context = new Context();
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var task = test();
            task.ContinueWith(_ => context.Complete(), TaskScheduler.Default);
            context.RunUntilComplete();
            task.GetAwaiter().GetResult();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
    }

    private sealed class Context : SynchronizationContext
    {
        private readonly BlockingCollection<(SendOrPostCallback, object?)> queue = [];

        public override void Post(SendOrPostCallback d, object? state) => queue.Add((d, state));

        public override void Send(SendOrPostCallback d, object? state) => throw new NotSupportedException();

        public void Complete() => queue.CompleteAdding();

        public void RunUntilComplete()
        {
            foreach (var (callback, state) in queue.GetConsumingEnumerable()) callback(state);
        }
    }
}
