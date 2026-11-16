// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Globalization;
using System.Text.RegularExpressions;

sealed record BenchmarkOptions(
    string Command,
    string? SourceShare,
    string? TargetShare,
    int FileCount,
    string ResultsDirectory,
    string? JobPath);

static partial class CommandLine
{
    public const string ConnectionStringVariable = "AZURE_STORAGE_CONNECTION_STRING";

    public static void PrintUsage()
    {
        Console.Error.WriteLine("Usage:");
        Console.Error.WriteLine("  dotnet run -- run --source-share <name> --target-share <name> [--file-count 1000] [--results ./results]");
        Console.Error.WriteLine("  dotnet run -- resume --job <path-to-job.json>");
        Console.Error.WriteLine("  dotnet run -- self-test");
        Console.Error.WriteLine();
        Console.Error.WriteLine($"Set {ConnectionStringVariable} to the storage account connection string before running.");
    }

    public static BenchmarkOptions? Parse(string[] args, out string? error)
    {
        error = null;
        if (args.Length == 0 || (args[0] != "run" && args[0] != "resume")) return null;

        var allowed = args[0] == "run"
            ? new HashSet<string>(StringComparer.Ordinal) { "source-share", "target-share", "file-count", "results" }
            : new HashSet<string>(StringComparer.Ordinal) { "job" };
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Length; i += 2)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            {
                error = $"Unexpected argument: {args[i]}";
                return null;
            }
            var key = args[i][2..];
            if (!allowed.Contains(key) || !values.TryAdd(key, args[i + 1]))
            {
                error = $"Unknown or duplicate option: {args[i]}";
                return null;
            }
        }

        if (args[0] == "resume")
        {
            if (!values.TryGetValue("job", out var job))
            {
                error = "resume requires --job.";
                return null;
            }
            return new BenchmarkOptions("resume", null, null, 0, "", job);
        }

        if (!values.TryGetValue("source-share", out var source) || !values.TryGetValue("target-share", out var target))
        {
            error = "run requires --source-share and --target-share.";
            return null;
        }
        if (!IsValidShareName(source) || !IsValidShareName(target))
        {
            error = "Share names must be 3-63 lowercase letters, digits, or single hyphens.";
            return null;
        }
        if (string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
        {
            error = "Source and target shares must be different.";
            return null;
        }

        var fileCount = 1000;
        if (values.TryGetValue("file-count", out var countText) &&
            (!int.TryParse(countText, NumberStyles.None, CultureInfo.InvariantCulture, out fileCount) ||
             fileCount < 40 || fileCount > 100_000 || fileCount % 40 != 0))
        {
            error = "--file-count must be between 40 and 100000 and divisible by 40 (for an exact 10% change set).";
            return null;
        }

        return new BenchmarkOptions("run", source, target, fileCount,
            values.GetValueOrDefault("results", "results"), null);
    }

    public static bool IsValidShareName(string? name) => name is not null && ShareName().IsMatch(name);

    [GeneratedRegex("^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$")]
    private static partial Regex ShareName();
}
