// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Storage.Files.Shares.Models;

/// <summary>Offline checks for the planning, path, argument, and request-classification logic.</summary>
static class SelfTests
{
    public static int Run()
    {
        var checks = 0;
        void Check(bool success, string name)
        {
            if (!success) throw new InvalidOperationException($"Self-test failed: {name}");
            checks++;
        }

        FileState State(string path, string id, string etag) =>
            new(path, id, etag, 8192, null, null, NtfsFileAttributes.Archive,
                "application/octet-stream", new Dictionary<string, string> { ["a"] = "b" });

        var before = new Dictionary<string, FileState>
        {
            ["same"] = State("same", "1", "a"),
            ["write"] = State("write", "2", "a"),
            ["old"] = State("old", "3", "a"),
            ["delete"] = State("delete", "4", "a")
        };
        var after = new Dictionary<string, FileState>
        {
            ["same"] = State("same", "1", "a"),
            ["write"] = State("write", "2", "b"),
            ["new"] = State("new", "3", "b"),
            ["add"] = State("add", "5", "a")
        };
        var plan = Incremental.Plan(before, after);
        Check(plan.Count == 5 && plan.Count(a => a.Kind == "Copy") == 3 && plan.Count(a => a.Kind == "Delete") == 2, "delta shape");
        Check(!plan.Any(a => a.Path == "same"), "metadata dictionaries use value equality");
        Check(Incremental.Plan(before, before).Count == 0, "no-change delta");

        var affected = Incremental.Affected(before,
        [
            new("SmbExtend", "2", null, null, false),
            new("RestRename", "3", "run/old", "run/new", false),
            new("RestDelete", "4", "run/delete", null, false),
            new("RestCreate", "5", "run/add", null, false),
            new("RestWrite", "unrelated", "other/file", null, false)
        ], "run");
        Check(affected.SetEquals(["write", "old", "new", "delete", "add"]), "file-ID/path/rename/delete correlation");
        Check(Incremental.Relative("run-other/file", "run") is null, "scope boundary");
        Check(Incremental.Relative("\\run\\group\\file", "run") == "group/file", "path normalization");

        var rejected = false;
        try { Incremental.Relative("run/../outside", "run"); } catch (InvalidOperationException) { rejected = true; }
        Check(rejected, "reject traversal");
        rejected = false;
        try { Incremental.Affected(before, [new("RestRename", "9", "run/dir", null, true)], "run"); }
        catch (NotSupportedException) { rejected = true; }
        Check(rejected, "unsupported directory mutations fail explicitly");

        using var list = new HttpRequestMessage(HttpMethod.Get, "https://a.file.core.windows.net/s/d?restype=directory&comp=list&marker=next");
        Check(HttpTransactions.Classify(list) == ("List", "ListDirectory"), "list page classification");
        using var blob = new HttpRequestMessage(HttpMethod.Get, "https://a.blob.core.windows.net/c/log");
        Check(HttpTransactions.Classify(blob) == ("Read", "ReadBlob"), "feed blob read classification");
        using var head = new HttpRequestMessage(HttpMethod.Head, "https://a.file.core.windows.net/s/f");
        Check(HttpTransactions.Classify(head) == ("Read", "GetFileProperties"), "properties are reads");
        using var copy = new HttpRequestMessage(HttpMethod.Put, "https://a.file.core.windows.net/s/f");
        copy.Headers.Add("x-ms-copy-source", "https://a.file.core.windows.net/src/f");
        Check(HttpTransactions.Classify(copy) == ("Write", "CopyFile"), "server-side copy is a write request");
        using var delete = new HttpRequestMessage(HttpMethod.Delete, "https://a.file.core.windows.net/s/f");
        Check(HttpTransactions.Classify(delete) == ("Write", "Delete"), "delete classification");

        var ok = CommandLine.Parse(["run", "--source-share", "src", "--target-share", "dst", "--file-count", "80"], out _);
        Check(ok is { SourceShare: "src", TargetShare: "dst", FileCount: 80, ResultsDirectory: "results" }, "parse run options");
        Check(CommandLine.Parse(["run", "--source-share", "same", "--target-share", "same"], out _) is null, "reject identical shares");
        Check(CommandLine.Parse(["run", "--source-share", "src", "--target-share", "dst", "--file-count", "50"], out _) is null, "reject uneven file count");
        Check(CommandLine.Parse(["run", "--source-share", "Bad_Name", "--target-share", "dst"], out _) is null, "reject invalid share name");
        Check(CommandLine.Parse(["run", "--source-share", "src", "--target-share", "dst", "--unknown", "x"], out _) is null, "reject unknown option");
        Check(CommandLine.Parse(["resume", "--job", "job.json"], out _) is { JobPath: "job.json" }, "parse resume options");

        Console.WriteLine($"PASS: {checks} offline checks.");
        return 0;
    }
}
