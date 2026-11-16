// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Storage.Files.Shares;
using Azure.Storage.Files.Shares.ChangeFeed;
using Azure.Storage.Files.Shares.Models;

/// <summary>
/// Copies an isolated test folder from a source share to a target share, then performs the same
/// incremental copy twice: once by scanning the whole folder (List + Get Properties) and once by
/// reading Azure Files change feed between two share snapshots. Both copies are validated, and every
/// HTTP request to the storage account is counted per phase.
/// </summary>
sealed class CopyBenchmark
{
    public const string RunIdPrefix = "cfcopy-";
    const int Concurrency = 16;
    static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    readonly CopyJob job;
    readonly string reportPath;
    readonly HttpTransactions meter;
    readonly ShareClient source;
    readonly ShareClient target;
    readonly CancellationToken ct;

    CopyBenchmark(CopyJob state, string path, HttpTransactions transactions, ShareServiceClient service, CancellationToken token)
    {
        job = state;
        reportPath = path;
        meter = transactions;
        ct = token;
        source = service.GetShareClient(job.SourceShare);
        target = service.GetShareClient(job.TargetShare);
    }

    public static async Task<int> RunAsync(BenchmarkOptions options)
    {
        CopyJob? state = null;
        CopyBenchmark? benchmark = null;
        try
        {
            var connectionString = Environment.GetEnvironmentVariable(CommandLine.ConnectionStringVariable);
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException($"Set {CommandLine.ConnectionStringVariable} to the storage account connection string.");

            // Change feed requires File service version 2026-02-06 or later.
            var clientOptions = new ShareClientOptions(ShareClientOptions.ServiceVersion.V2026_02_06);
            clientOptions.Retry.MaxRetries = 3;
            clientOptions.Retry.NetworkTimeout = TimeSpan.FromSeconds(30);
            var service = new ShareServiceClient(connectionString, clientOptions);

            string path;
            if (options.Command == "resume")
            {
                path = Path.GetFullPath(options.JobPath!);
                state = JsonSerializer.Deserialize<CopyJob>(await File.ReadAllTextAsync(path), JsonOptions)
                    ?? throw new InvalidOperationException("The job file is empty.");
                if (!string.Equals(state.Account, service.AccountName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The job file belongs to a different storage account than the connection string.");
                if (!state.RunId.StartsWith(RunIdPrefix, StringComparison.Ordinal) || state.RunId.Contains('/') || state.RunId.Contains('\\') ||
                    !CommandLine.IsValidShareName(state.SourceShare) || !CommandLine.IsValidShareName(state.TargetShare))
                    throw new InvalidOperationException("The job file is not a valid checkpoint for this sample.");
            }
            else
            {
                state = new CopyJob
                {
                    Account = service.AccountName,
                    SourceShare = options.SourceShare!,
                    TargetShare = options.TargetShare!,
                    FileCount = options.FileCount
                };
                var output = Path.GetFullPath(options.ResultsDirectory);
                Directory.CreateDirectory(output);
                path = Path.Combine(output, state.RunId + ".json");
                if (File.Exists(path)) throw new IOException("Job report already exists.");
            }

            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(90));
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; timeout.Cancel(); };
            var fileHost = service.Uri.Host;
            var blobHost = fileHost.Replace(".file.", ".blob.", StringComparison.OrdinalIgnoreCase);
            using var transactions = new HttpTransactions(fileHost, blobHost, state.Requests);
            benchmark = new CopyBenchmark(state, path, transactions, service, timeout.Token);
            state.Failure = null;
            benchmark.Save();
            Console.WriteLine($"Job: {state.RunId}");
            Console.WriteLine($"Source: {state.Account}/{state.SourceShare}/{state.RunId}");
            Console.WriteLine($"Target: {state.Account}/{state.TargetShare}/{state.RunId}");
            Console.WriteLine($"Report: {path}");
            await benchmark.ExecuteAsync();
            return 0;
        }
        catch (Exception ex)
        {
            var error = ex is RequestFailedException request
                ? $"Azure request failed: HTTP {request.Status}, error code {request.ErrorCode}."
                : ex is AggregateException ? "A parallel REST operation failed. Resume the job to retry." : ex.Message;
            Console.Error.WriteLine(error);
            if (state is not null && benchmark is not null)
            {
                state.Failure = error;
                benchmark.Save();
                Console.Error.WriteLine("The job checkpoint was saved. Use 'resume' to continue. No data or snapshots were deleted.");
            }
            return 1;
        }
    }

    async Task ExecuteAsync()
    {
        await PhaseAsync("setup.authentication", async () =>
        {
            var previous = meter.Snapshot().Sum(r => r.Count);
            var properties = (await source.GetPropertiesAsync(ct)).Value;
            if (properties.EnableChangeFeed != true)
                throw new InvalidOperationException($"Change feed is not enabled on share '{job.SourceShare}'.");
            if (meter.Snapshot().Sum(r => r.Count) <= previous)
                throw new InvalidOperationException("HTTP request instrumentation did not observe the first request.");
            Console.WriteLine("Authenticated; change feed is enabled on the source share.");
        });

        if (job.SnapshotA is null)
        {
            await PhaseAsync("setup.target", async () =>
            {
                await target.CreateIfNotExistsAsync(cancellationToken: ct);
                await EnsureDirectoryAsync(source, job.RunId);
                await EnsureDirectoryAsync(target, $"{job.RunId}/scan");
                await EnsureDirectoryAsync(target, $"{job.RunId}/changefeed");
                foreach (var group in Enumerable.Range(0, 10))
                {
                    await EnsureDirectoryAsync(source, $"{job.RunId}/group-{group:D2}");
                    await EnsureDirectoryAsync(target, $"{job.RunId}/scan/group-{group:D2}");
                    await EnsureDirectoryAsync(target, $"{job.RunId}/changefeed/group-{group:D2}");
                }
            });
            await PhaseAsync("setup.populate", async () =>
                await ParallelAsync(Enumerable.Range(0, job.FileCount), async i =>
                    await PutTestFileAsync(Original(i), i, version: 1, create: true)));
            await PhaseAsync("setup.snapshot-a", async () =>
                job.SnapshotA = (await source.CreateSnapshotAsync(cancellationToken: ct)).Value.Snapshot);
        }

        var beforeSource = source.WithSnapshot(job.SnapshotA);
        if (job.Before.Count == 0)
            await PhaseAsync("baseline.scan", async () => job.Before = await ScanAsync(beforeSource, job.RunId));
        if (job.Before.Count != job.FileCount) throw new InvalidOperationException("Baseline file count mismatch.");

        if (!job.BaselinesCopied)
        {
            var baseline = job.Before.Keys.Select(p => new CopyAction("Copy", p)).ToList();
            await PhaseAsync("baseline.scan-copy", async () => await ApplyAsync(beforeSource, "scan", baseline, job.Before));
            await PhaseAsync("baseline.feed-copy", async () => await ApplyAsync(beforeSource, "changefeed", baseline, job.Before));
            job.BaselinesCopied = true;
            Save();
        }

        if (job.SnapshotB is null)
        {
            await PhaseAsync("setup.mutations", MutateAsync);
            await PhaseAsync("setup.snapshot-b", async () =>
                job.SnapshotB = (await source.CreateSnapshotAsync(cancellationToken: ct)).Value.Snapshot);
        }
        var afterSource = source.WithSnapshot(job.SnapshotB);

        // Method 1: full scan of the folder in snapshot B, compared with the baseline index.
        if (!job.ScanDetected)
        {
            await PhaseAsync("scan.detection", async () =>
            {
                job.ScanAfter = await ScanAsync(afterSource, job.RunId);
                job.ScanPlan = Incremental.Plan(job.Before, job.ScanAfter);
                job.ScanDetected = true;
            });
        }

        // Method 2: change feed between snapshots A and B; only affected paths are inspected.
        if (!job.FeedDetected)
        {
            var feed = source.GetShareChangeFeedClient();
            await PhaseAsync("feed.finalization-poll", async () =>
            {
                var deadline = DateTimeOffset.UtcNow.AddMinutes(25);
                while (true)
                {
                    var a = await feed.GetSnapshotStatusAsync(job.SnapshotA, ct);
                    var b = await feed.GetSnapshotStatusAsync(job.SnapshotB, ct);
                    Console.WriteLine($"Change feed snapshot status: A={a}, B={b}");
                    if (a == ShareChangeFeedSnapshotStatus.Finalized && b == ShareChangeFeedSnapshotStatus.Finalized) break;
                    if (DateTimeOffset.UtcNow >= deadline)
                        throw new TimeoutException("The snapshots aren't finalized in the change feed yet. Resume the job later.");
                    await Task.Delay(TimeSpan.FromSeconds(30), ct);
                }
            });
            await PhaseAsync("feed.detection", async () =>
            {
                var changes = new List<FeedChange>();
                job.ShareWideFeedEvents = 0;
                await foreach (var item in feed.GetChangesBetweenSnapshotsAsync(job.SnapshotA, job.SnapshotB).WithCancellation(ct))
                {
                    job.ShareWideFeedEvents++;
                    if (item.Reason == ShareChangeFeedReasonKind.ControlEvent) continue;
                    var data = item.EventData;
                    if (data is null) continue;
                    changes.Add(new FeedChange(item.Reason.ToString(), data.FileId ?? "",
                        data.FullFilePath, data.NewFullFilePath, data.IsDirectory));
                }
                var affected = Incremental.Affected(job.Before, changes, job.RunId);
                var beforeIds = job.Before.Values.Select(f => f.FileId).ToHashSet(StringComparer.Ordinal);
                job.FeedEvents = changes.Where(e => beforeIds.Contains(e.FileId) ||
                    Incremental.Relative(e.Path, job.RunId) is not null || Incremental.Relative(e.NewPath, job.RunId) is not null).ToList();
                var current = new ConcurrentDictionary<string, FileState>(job.Before, StringComparer.Ordinal);
                await ParallelAsync(affected, async relative =>
                {
                    var state = await ReadStateOrMissingAsync(afterSource, job.RunId, relative);
                    if (state is null) current.TryRemove(relative, out _);
                    else current[relative] = state;
                });
                job.FeedAfter = current.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
                job.FeedPlan = Incremental.Plan(job.Before, job.FeedAfter);
                job.FeedDetected = true;
            });
        }

        if (!job.ScanPlan.SequenceEqual(job.FeedPlan))
            throw new InvalidOperationException("The full scan and the change feed produced different copy plans. No incremental changes were applied to the target.");
        if (job.ScanAfter.Count != job.FileCount || job.ScanPlan.Count(a => a.Kind == "Copy") != job.FileCount * 3 / 40 ||
            job.ScanPlan.Count(a => a.Kind == "Delete") != job.FileCount * 2 / 40)
            throw new InvalidOperationException("The detected changes don't match the controlled 10% workload.");
        Console.WriteLine($"Both methods produced the same plan: {job.ScanPlan.Count(a => a.Kind == "Copy")} copies, {job.ScanPlan.Count(a => a.Kind == "Delete")} deletions.");

        if (!job.ScanCopied)
        {
            await PhaseAsync("scan.copy", async () => await ApplyAsync(afterSource, "scan", job.ScanPlan, job.ScanAfter));
            job.ScanCopied = true;
            Save();
        }
        if (!job.FeedCopied)
        {
            await PhaseAsync("feed.copy", async () => await ApplyAsync(afterSource, "changefeed", job.FeedPlan, job.FeedAfter));
            job.FeedCopied = true;
            Save();
        }

        await PhaseAsync("validation.source", async () =>
        {
            var hashes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
            await ParallelAsync(job.ScanAfter.Keys, async p =>
                hashes[p] = await HashAsync(FileClient(afterSource, $"{job.RunId}/{p}")));
            job.ValidatedHashes = hashes.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        });
        await PhaseAsync("validation.scan", async () => await ValidateAsync("scan"));
        await PhaseAsync("validation.feed", async () => await ValidateAsync("changefeed"));
        job.Verified = true;
        job.VerifiedTargetFiles = job.FileCount * 2;
        job.FinishedUtc = DateTimeOffset.UtcNow;
        Save();
        WriteSummary();
        Console.WriteLine("PASS: both incremental copies match snapshot B (paths, sizes, SHA-256 contents, SMB attributes and timestamps, and metadata).");
    }

    /// <summary>Applies an exact 10% change set: creates, in-place writes, renames, and deletes in equal parts.</summary>
    async Task MutateAsync()
    {
        var each = job.FileCount / 40;
        for (var index = job.MutationsCompleted; index < each * 4; index++)
        {
            var n = index % each;
            if (index < each)
                await PutTestFileAsync($"group-{n % 10:D2}/added-{n:D6}.bin", n, 2, create: true);
            else if (index < each * 2)
                await PutTestFileAsync(Original(n), n, 2, create: false);
            else if (index < each * 3)
            {
                var relative = Original(each + n);
                var renamed = relative.Replace("file-", "renamed-", StringComparison.Ordinal);
                if ((await FileClient(source, $"{job.RunId}/{relative}").ExistsAsync(ct)).Value)
                    await FileClient(source, $"{job.RunId}/{relative}").RenameAsync($"{job.RunId}/{renamed}", cancellationToken: ct);
                else if (!(await FileClient(source, $"{job.RunId}/{renamed}").ExistsAsync(ct)).Value)
                    throw new InvalidOperationException("Neither the original nor the renamed test file exists.");
            }
            else
                await FileClient(source, $"{job.RunId}/{Original(each * 2 + n)}").DeleteIfExistsAsync(cancellationToken: ct);
            job.MutationsCompleted = index + 1;
            Save();
        }
        Console.WriteLine($"Changes applied: {each} creates, {each} in-place writes, {each} renames, {each} deletes.");
    }

    async Task PutTestFileAsync(string relative, int index, int version, bool create)
    {
        var file = FileClient(source, $"{job.RunId}/{relative}");
        if (create)
            await file.CreateAsync(job.FileBytes, new ShareFileCreateOptions
            {
                Metadata = new Dictionary<string, string> { ["sample"] = job.RunId, ["version"] = version.ToString(CultureInfo.InvariantCulture) },
                HttpHeaders = new ShareFileHttpHeaders { ContentType = "application/octet-stream" }
            }, cancellationToken: ct);
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes($"{job.RunId}:{index}:{version}"));
        var bytes = new byte[job.FileBytes];
        for (var offset = 0; offset < bytes.Length; offset++) bytes[offset] = seed[offset % seed.Length];
        using var content = new MemoryStream(bytes, writable: false);
        await file.UploadRangeAsync(new HttpRange(0, bytes.Length), content, cancellationToken: ct);
    }

    /// <summary>Full scan: recursive List Directories and Files plus Get File Properties for every file.</summary>
    async Task<Dictionary<string, FileState>> ScanAsync(ShareClient share, string root)
    {
        var files = new List<string>();
        await WalkAsync(share.GetDirectoryClient(root), "", files);
        var index = new ConcurrentDictionary<string, FileState>(StringComparer.Ordinal);
        await ParallelAsync(files, async p =>
        {
            index[p] = await ReadStateOrMissingAsync(share, root, p)
                ?? throw new InvalidOperationException("A listed file disappeared during the scan.");
        });
        return index.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
    }

    async Task WalkAsync(ShareDirectoryClient directory, string relative, List<string> files)
    {
        await foreach (var item in directory.GetFilesAndDirectoriesAsync(cancellationToken: ct))
        {
            var path = string.IsNullOrEmpty(relative) ? item.Name : $"{relative}/{item.Name}";
            if (item.IsDirectory) await WalkAsync(directory.GetSubdirectoryClient(item.Name), path, files);
            else files.Add(path);
        }
    }

    async Task<FileState?> ReadStateOrMissingAsync(ShareClient share, string root, string relative)
    {
        try
        {
            var value = (await FileClient(share, $"{root}/{relative}").GetPropertiesAsync(cancellationToken: ct)).Value;
            return new FileState(relative, value.SmbProperties.FileId, value.ETag.ToString(), value.ContentLength,
                value.SmbProperties.FileCreatedOn, value.SmbProperties.FileLastWrittenOn, value.SmbProperties.FileAttributes,
                value.ContentType, new Dictionary<string, string>(value.Metadata, StringComparer.OrdinalIgnoreCase));
        }
        catch (RequestFailedException ex) when (ex.Status == 404 && ex.ErrorCode is "ResourceNotFound" or "FileNotFound")
        {
            return null;
        }
    }

    /// <summary>Applies a plan to the target with server-side Copy File from the immutable source snapshot.</summary>
    async Task ApplyAsync(ShareClient snapshot, string method, List<CopyAction> plan, Dictionary<string, FileState> index)
    {
        await ParallelAsync(plan.Where(a => a.Kind == "Delete"), async action =>
            await FileClient(target, $"{job.RunId}/{method}/{action.Path}").DeleteIfExistsAsync(cancellationToken: ct));
        await ParallelAsync(plan.Where(a => a.Kind == "Copy"), async action =>
        {
            var state = index[action.Path];
            var src = FileClient(snapshot, $"{job.RunId}/{action.Path}");
            var dst = FileClient(target, $"{job.RunId}/{method}/{action.Path}");
            // Same-account copy: the source is authorized with the destination request's Shared Key.
            var result = (await dst.StartCopyAsync(src.Uri, new ShareFileCopyOptions
            {
                Metadata = state.Metadata,
                SmbProperties = new FileSmbProperties
                {
                    FileCreatedOn = state.CreatedUtc,
                    FileLastWrittenOn = state.WrittenUtc,
                    FileAttributes = state.Attributes
                },
                FilePermissionCopyMode = PermissionCopyMode.Source
            }, cancellationToken: ct)).Value;
            var status = result.CopyStatus;
            var deadline = DateTimeOffset.UtcNow.AddMinutes(5);
            while (status == CopyStatus.Pending)
            {
                if (DateTimeOffset.UtcNow >= deadline) throw new TimeoutException("A server-side file copy didn't finish within five minutes.");
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct);
                var properties = (await dst.GetPropertiesAsync(cancellationToken: ct)).Value;
                if (properties.CopyId != result.CopyId) throw new InvalidOperationException("The destination copy ID changed unexpectedly.");
                status = properties.CopyStatus;
            }
            if (status != CopyStatus.Success) throw new InvalidOperationException("A server-side file copy didn't succeed.");
        });
    }

    async Task ValidateAsync(string method)
    {
        var root = $"{job.RunId}/{method}";
        var current = await ScanAsync(target, root);
        if (!current.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(job.ScanAfter.Keys))
            throw new InvalidOperationException($"{method}: the target file list differs from snapshot B.");
        await ParallelAsync(current.Values, async actual =>
        {
            var expected = job.ScanAfter[actual.Path];
            if (actual.Length != expected.Length || actual.WrittenUtc != expected.WrittenUtc ||
                actual.CreatedUtc != expected.CreatedUtc || actual.Attributes != expected.Attributes ||
                actual.ContentType != expected.ContentType || !Incremental.MetadataEqual(actual.Metadata, expected.Metadata))
                throw new InvalidOperationException($"{method}: properties differ at {actual.Path}.");
            if (await HashAsync(FileClient(target, $"{root}/{actual.Path}")) != job.ValidatedHashes[actual.Path])
                throw new InvalidOperationException($"{method}: content differs at {actual.Path}.");
        });
        Console.WriteLine($"{method}: verified {current.Count} target files.");
    }

    async Task<string> HashAsync(ShareFileClient file)
    {
        var download = (await file.DownloadAsync(cancellationToken: ct)).Value;
        using var stream = download.Content;
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
    }

    async Task EnsureDirectoryAsync(ShareClient share, string path)
    {
        var directory = share.GetRootDirectoryClient();
        foreach (var part in path.Split('/'))
        {
            directory = directory.GetSubdirectoryClient(part);
            await directory.CreateIfNotExistsAsync(cancellationToken: ct);
        }
    }

    static ShareFileClient FileClient(ShareClient share, string path)
    {
        var parts = path.Split('/');
        if (parts.Any(p => p is "" or "." or "..")) throw new ArgumentException("Unsafe file path.");
        var directory = share.GetRootDirectoryClient();
        foreach (var part in parts[..^1]) directory = directory.GetSubdirectoryClient(part);
        return directory.GetFileClient(parts[^1]);
    }

    static string Original(int i) => $"group-{i % 10:D2}/file-{i:D6}.bin";

    async Task ParallelAsync<T>(IEnumerable<T> items, Func<T, Task> action) =>
        await Parallel.ForEachAsync(items, new ParallelOptions { MaxDegreeOfParallelism = Concurrency, CancellationToken = ct },
            async (item, _) => await action(item));

    async Task PhaseAsync(string name, Func<Task> action)
    {
        meter.SetPhase(name);
        var watch = Stopwatch.StartNew();
        Console.WriteLine($"Starting {name}");
        try { await action(); }
        finally
        {
            watch.Stop();
            job.PhaseSeconds[name] = job.PhaseSeconds.GetValueOrDefault(name) + watch.Elapsed.TotalSeconds;
            Save();
            meter.SetPhase("between-phases");
        }
        if (meter.Fault is not null) throw new InvalidOperationException(meter.Fault);
    }

    void Save()
    {
        job.Requests = meter.Snapshot();
        var temporary = reportPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(job, JsonOptions));
        File.Move(temporary, reportPath, overwrite: true);
    }

    void WriteSummary()
    {
        var text = new StringBuilder("Phase,List,Read,Write,Other,Total,Seconds\n");
        foreach (var group in job.Requests.GroupBy(r => r.Phase).OrderBy(g => g.Key))
        {
            long Count(string category) => group.Where(r => r.Category == category).Sum(r => r.Count);
            text.AppendLine(string.Join(",", group.Key, Count("List"), Count("Read"), Count("Write"),
                Count("Other"), group.Sum(r => r.Count),
                job.PhaseSeconds.GetValueOrDefault(group.Key).ToString("F3", CultureInfo.InvariantCulture)));
        }
        var csv = Path.ChangeExtension(reportPath, ".csv");
        File.WriteAllText(csv, text.ToString());
        Console.WriteLine(text.ToString());
        Console.WriteLine($"Request summary: {csv}");
    }
}
