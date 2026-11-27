using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Riot.Agent;

public sealed class DaemonException(string code, string message) : Exception($"{code}: {message}")
{
    /// <summary><c>badRequest</c> | <c>forbidden</c> | <c>unavailable</c> | <c>internal</c>, or
    /// <c>closed</c> and <c>timeout</c> on this side.</summary>
    public string Code { get; } = code;
}

/// <summary>
/// Line-delimited JSON over the daemon's named pipe (protocol: core/riot-ipc). One connection
/// carries both replies and pushed events; replies are matched to callers by <c>id</c>.
/// </summary>
public sealed class DaemonClient : IDisposable
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const string PipePrefix = @"\\.\pipe\";

    /// <summary><c>RIOT_SOCKET</c> (<c>\\.\pipe\riot-dev</c>), or the installed daemon's.</summary>
    public static string PipeName
    {
        get
        {
            var path = Environment.GetEnvironmentVariable("RIOT_SOCKET");
            if (string.IsNullOrEmpty(path)) return "com.tryriot.agent";
            return path.StartsWith(PipePrefix, StringComparison.OrdinalIgnoreCase) ? path[PipePrefix.Length..] : path;
        }
    }

    private readonly NamedPipeClientStream pipe;
    private readonly SemaphoreSlim writeLock = new(1, 1);
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonNode?>> pending = new();
    private readonly Action<DaemonEvent> onEvent;
    private readonly Action onClose;
    private long nextId;
    private int closed;

    private DaemonClient(NamedPipeClientStream pipe, Action<DaemonEvent> onEvent, Action onClose)
    {
        this.pipe = pipe;
        this.onEvent = onEvent;
        this.onClose = onClose;
        _ = Task.Run(ReadLoop);
    }

    /// <summary><paramref name="onEvent"/> and <paramref name="onClose"/> run on a background
    /// thread.</summary>
    public static async Task<DaemonClient> Connect(Action<DaemonEvent> onEvent, Action onClose, string? pipeName = null,
        CancellationToken cancel = default)
    {
        var pipe = new NamedPipeClientStream(".", pipeName ?? PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(TimeSpan.FromSeconds(2), cancel);
        }
        catch
        {
            await pipe.DisposeAsync();
            throw;
        }
        return new DaemonClient(pipe, onEvent, onClose);
    }

    public async Task<T> Call<T>(string method, object? parameters = null, TimeSpan? timeout = null)
    {
        var node = await CallRaw(method, parameters, timeout);
        return node.Deserialize<T>(Json) ?? throw new DaemonException("internal", $"empty reply to {method}");
    }

    public Task Call(string method, object? parameters = null, TimeSpan? timeout = null) => CallRaw(method, parameters, timeout);

    private async Task<JsonNode?> CallRaw(string method, object? parameters, TimeSpan? timeout)
    {
        if (Volatile.Read(ref closed) != 0) throw new DaemonException("closed", "connection closed");
        var id = Interlocked.Increment(ref nextId);
        var reply = new TaskCompletionSource<JsonNode?>(TaskCreationOptions.RunContinuationsAsynchronously);
        pending[id] = reply;
        var envelope = new JsonObject { ["id"] = id, ["method"] = method };
        if (parameters is not null) envelope["params"] = JsonSerializer.SerializeToNode(parameters, Json);
        var line = Encoding.UTF8.GetBytes(envelope.ToJsonString() + "\n");
        try
        {
            await writeLock.WaitAsync();
            try
            {
                await pipe.WriteAsync(line);
                await pipe.FlushAsync();
            }
            finally
            {
                writeLock.Release();
            }
            return await reply.Task.WaitAsync(timeout ?? TimeSpan.FromSeconds(15));
        }
        catch (TimeoutException)
        {
            throw new DaemonException("timeout", $"no reply to {method}");
        }
        catch (IOException)
        {
            Close();
            throw new DaemonException("closed", "connection closed");
        }
        finally
        {
            pending.TryRemove(id, out _);
        }
    }

    private async Task ReadLoop()
    {
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            while (await reader.ReadLineAsync() is { } line)
            {
                Handle(line);
            }
        }
        catch (Exception)
        {
            // the pipe broke: closed below
        }
        Close();
    }

    private void Handle(string line)
    {
        JsonObject? message;
        try
        {
            message = JsonNode.Parse(line) as JsonObject;
        }
        catch (JsonException)
        {
            return;
        }
        if (message is null) return;
        if (message["event"]?.GetValue<string>() is { } name)
        {
            DaemonEvent? daemonEvent = name switch
            {
                "fileBlocked" => message["data"].Deserialize<FileBlocked>(Json) is { } file ? new DaemonEvent.Blocked(file) : null,
                _ => new DaemonEvent.StateChanged(),
            };
            if (daemonEvent is not null) onEvent(daemonEvent);
            return;
        }
        if (message["id"]?.GetValue<long>() is not { } id || !pending.TryRemove(id, out var reply)) return;
        if (message["error"] is JsonObject error)
        {
            reply.TrySetException(new DaemonException(
                error["code"]?.GetValue<string>() ?? "internal", error["message"]?.GetValue<string>() ?? ""));
        }
        else
        {
            reply.TrySetResult(message["ok"]);
        }
    }

    private void Close()
    {
        if (Interlocked.Exchange(ref closed, 1) != 0) return;
        pipe.Dispose();
        foreach (var reply in pending.Values) reply.TrySetException(new DaemonException("closed", "connection closed"));
        pending.Clear();
        onClose();
    }

    public void Dispose() => Close();
}
