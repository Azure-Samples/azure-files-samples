// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

if (args.Length == 1 && args[0] == "self-test")
    return SelfTests.Run();

var options = CommandLine.Parse(args, out var error);
if (options is null)
{
    if (error is not null) Console.Error.WriteLine(error);
    CommandLine.PrintUsage();
    return 1;
}

return await CopyBenchmark.RunAsync(options);
