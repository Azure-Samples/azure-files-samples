// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Web;

sealed record RequestCount(string Phase, string Service, string Category, string Operation, string Method, long Count);

/// <summary>
/// Counts outgoing HTTP requests to the storage account's file and blob endpoints by observing
/// .NET HttpClient diagnostics. Only classifications and counts are kept, never URLs, headers, or keys.
/// </summary>
sealed class HttpTransactions : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
{
    readonly string fileHost;
    readonly string blobHost;
    readonly ConcurrentBag<IDisposable> subscriptions = [];
    readonly ConcurrentDictionary<(string Phase, string Service, string Category, string Operation, string Method), long> counts = [];
    readonly IDisposable allListeners;
    string phase = "startup";

    public string? Fault { get; private set; }

    public HttpTransactions(string fileEndpointHost, string blobEndpointHost, IEnumerable<RequestCount> previous)
    {
        fileHost = fileEndpointHost;
        blobHost = blobEndpointHost;
        foreach (var row in previous)
            counts[(row.Phase, row.Service, row.Category, row.Operation, row.Method)] = row.Count;
        allListeners = DiagnosticListener.AllListeners.Subscribe(this);
    }

    public void SetPhase(string value) => phase = value;

    public List<RequestCount> Snapshot() => counts
        .Select(p => new RequestCount(p.Key.Phase, p.Key.Service, p.Key.Category, p.Key.Operation, p.Key.Method, p.Value))
        .OrderBy(p => p.Phase).ThenBy(p => p.Service).ThenBy(p => p.Operation).ToList();

    public void OnNext(DiagnosticListener listener)
    {
        if (listener.Name == "HttpHandlerDiagnosticListener")
            subscriptions.Add(listener.Subscribe(this, name => name.StartsWith("System.Net.Http.HttpRequestOut", StringComparison.Ordinal)));
    }

    public void OnNext(KeyValuePair<string, object?> item)
    {
        if (item.Key != "System.Net.Http.HttpRequestOut.Start") return;
        if (item.Value?.GetType().GetProperty("Request")?.GetValue(item.Value) is not HttpRequestMessage request)
        {
            Fault = "HTTP diagnostics did not supply the expected request payload.";
            return;
        }
        var host = request.RequestUri?.Host;
        string service;
        if (string.Equals(host, fileHost, StringComparison.OrdinalIgnoreCase)) service = "Files";
        else if (string.Equals(host, blobHost, StringComparison.OrdinalIgnoreCase)) service = "Blob";
        else return;
        var classification = Classify(request);
        counts.AddOrUpdate((phase, service, classification.Category, classification.Operation, request.Method.Method),
            1, (_, value) => value + 1);
    }

    /// <summary>Classifies a request as List, Read, Write, or Other, with an operation name.</summary>
    public static (string Category, string Operation) Classify(HttpRequestMessage request)
    {
        var query = HttpUtility.ParseQueryString(request.RequestUri!.Query);
        var comp = query["comp"];
        var type = query["restype"];
        var blob = request.RequestUri.Host.Contains(".blob.", StringComparison.OrdinalIgnoreCase);
        if (request.Method == HttpMethod.Get && comp == "list")
            return ("List", blob ? "ListBlobs" : "ListDirectory");
        if (request.Method == HttpMethod.Head)
            return ("Read", blob ? "GetBlobProperties" : type == "share" ? "GetShareProperties" : "GetFileProperties");
        if (request.Method == HttpMethod.Get)
            return ("Read", blob ? "ReadBlob" : "ReadFile");
        if (request.Method == HttpMethod.Put || request.Method == HttpMethod.Delete || request.Method == HttpMethod.Post)
        {
            var operation = request.Method == HttpMethod.Delete ? "Delete" :
                request.Headers.Contains("x-ms-copy-source") ? "CopyFile" :
                request.Headers.Contains("x-ms-file-rename-source") ? "RenameFile" :
                comp == "snapshot" ? "SnapshotShare" :
                comp == "range" ? "PutRange" :
                comp == "properties" ? "SetProperties" :
                type == "share" ? "CreateShare" :
                type == "directory" ? "CreateDirectory" : "CreateFile";
            return ("Write", operation);
        }
        return ("Other", request.Method.Method);
    }

    public void OnError(Exception error) => Fault = "The HTTP diagnostic stream failed.";

    public void OnCompleted() { }

    public void Dispose()
    {
        allListeners.Dispose();
        foreach (var subscription in subscriptions) subscription.Dispose();
    }
}
