// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Storage.Files.Shares.Models;

sealed record FileState(string Path, string FileId, string ETag, long Length,
    DateTimeOffset? CreatedUtc, DateTimeOffset? WrittenUtc, NtfsFileAttributes? Attributes,
    string ContentType, Dictionary<string, string> Metadata);

sealed record CopyAction(string Kind, string Path);

sealed record FeedChange(string Reason, string FileId, string? Path, string? NewPath, bool Directory);

/// <summary>Checkpointed job state. Written to disk after every phase so a run can be resumed.</summary>
sealed class CopyJob
{
    public string Account { get; set; } = "";
    public string SourceShare { get; set; } = "";
    public string TargetShare { get; set; } = "";
    public string RunId { get; set; } = $"{CopyBenchmark.RunIdPrefix}{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
    public DateTimeOffset StartedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedUtc { get; set; }
    public int FileCount { get; set; } = 1000;
    public int FileBytes { get; set; } = 8192;
    public string? SnapshotA { get; set; }
    public string? SnapshotB { get; set; }
    public bool BaselinesCopied { get; set; }
    public int MutationsCompleted { get; set; }
    public bool ScanDetected { get; set; }
    public bool FeedDetected { get; set; }
    public bool ScanCopied { get; set; }
    public bool FeedCopied { get; set; }
    public bool Verified { get; set; }
    public string? Failure { get; set; }
    public Dictionary<string, FileState> Before { get; set; } = [];
    public Dictionary<string, FileState> ScanAfter { get; set; } = [];
    public Dictionary<string, FileState> FeedAfter { get; set; } = [];
    public List<CopyAction> ScanPlan { get; set; } = [];
    public List<CopyAction> FeedPlan { get; set; } = [];
    public List<FeedChange> FeedEvents { get; set; } = [];
    public long ShareWideFeedEvents { get; set; }
    public List<RequestCount> Requests { get; set; } = [];
    public Dictionary<string, double> PhaseSeconds { get; set; } = [];
    public Dictionary<string, string> ValidatedHashes { get; set; } = [];
    public int VerifiedTargetFiles { get; set; }
}

static class Incremental
{
    /// <summary>Builds a copy/delete plan by comparing two file indexes.</summary>
    public static List<CopyAction> Plan(Dictionary<string, FileState> before, Dictionary<string, FileState> after)
    {
        var actions = before.Keys.Except(after.Keys).Select(p => new CopyAction("Delete", p)).ToList();
        actions.AddRange(after.Values.Where(f => !before.TryGetValue(f.Path, out var old) || !Equal(old, f))
            .Select(f => new CopyAction("Copy", f.Path)));
        return actions.OrderBy(a => a.Kind).ThenBy(a => a.Path, StringComparer.Ordinal).ToList();
    }

    public static bool Equal(FileState a, FileState b) =>
        a.FileId == b.FileId && a.ETag == b.ETag && a.Length == b.Length &&
        a.CreatedUtc == b.CreatedUtc && a.WrittenUtc == b.WrittenUtc && a.Attributes == b.Attributes &&
        a.ContentType == b.ContentType && MetadataEqual(a.Metadata, b.Metadata);

    public static bool MetadataEqual(Dictionary<string, string> a, Dictionary<string, string> b) =>
        a.Count == b.Count && a.All(p => b.TryGetValue(p.Key, out var value) && value == p.Value);

    /// <summary>
    /// Returns every relative path that might differ between the two snapshots, based on change feed events.
    /// Some events (for example SmbExtend) carry only a file ID, so paths are also resolved through the baseline index.
    /// </summary>
    public static HashSet<string> Affected(Dictionary<string, FileState> before, IEnumerable<FeedChange> changes, string root)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var ids = before.Values.ToDictionary(f => f.FileId, f => f.Path, StringComparer.Ordinal);
        foreach (var change in changes)
        {
            var path = Relative(change.Path, root);
            var next = Relative(change.NewPath, root);
            if (path is null && next is null && !ids.ContainsKey(change.FileId)) continue;
            if (change.Directory) throw new NotSupportedException("This sample supports file changes, not directory mutations, inside the job folder.");
            if (path is not null) result.Add(path);
            if (next is not null) result.Add(next);
            if (ids.TryGetValue(change.FileId, out var previous)) result.Add(previous);
            if (path is not null && !string.IsNullOrEmpty(change.FileId)) ids[change.FileId] = next ?? path;
        }
        return result;
    }

    /// <summary>Converts a share-relative path to a path relative to the job root, or null if it is outside the root.</summary>
    public static string? Relative(string? path, string root)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var normalized = path.Replace('\\', '/').TrimStart('/');
        if (!normalized.StartsWith(root + "/", StringComparison.Ordinal)) return null;
        var relative = normalized[(root.Length + 1)..];
        if (relative.Split('/').Any(s => s is "" or "." or ".."))
            throw new InvalidOperationException("The feed contains an unsafe relative path.");
        return relative;
    }
}
