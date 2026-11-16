# Azure Files change feed: incremental copy sample

This .NET sample shows how to use [Azure Files change feed](https://learn.microsoft.com/azure/storage/files/storage-files-change-feed) to copy only what changed between two points in time, and compares that approach with a traditional full namespace scan.

The sample:

1. Creates an isolated test folder on a source share with synthetic files, then takes **share snapshot A**.
2. Copies the folder to a target share twice (into `scan/` and `changefeed/` subfolders) as a baseline.
3. Applies a controlled 10% change set to the source (creates, in-place writes, renames, and deletes), then takes **share snapshot B**.
4. Detects the changes in two independent ways:
   - **Full scan:** recursively lists the folder in snapshot B and gets the properties of every file, then compares the result with the baseline.
   - **Change feed:** reads the events between snapshots A and B with `GetChangesBetweenSnapshotsAsync`, and gets properties only for the affected files.
5. Requires both methods to produce the same copy plan, applies each plan to its own target folder with server-side **Copy File** from snapshot B, and validates both targets.
6. Reports the number of HTTP requests and the elapsed time for every phase, so you can compare the cost of the two detection methods.

All storage operations use the Azure Files REST API through the Azure SDK for .NET. No SMB or NFS mount is needed.

> [!IMPORTANT]
> Azure Files change feed is in preview, and this sample uses the prerelease `Azure.Storage.Files.Shares.ChangeFeed` package (`12.0.0-beta.1`). APIs can change before general availability. This sample is for learning and evaluation, not for production use.

## Prerequisites

- Preview access to Azure Files change feed for your subscription. To request access, [sign up for the preview](https://forms.cloud.microsoft/r/t47725qjsx).
- A storage account and file share that the preview supports. See [Feature support](https://learn.microsoft.com/azure/storage/files/storage-files-change-feed#feature-support).
- Change feed enabled on the storage account and on the **source** share. See [Enable and configure change feed](https://learn.microsoft.com/azure/storage/files/storage-files-change-feed#enable-and-configure-change-feed).
- The [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later.
- The storage account connection string. The account must allow Shared Key authorization.

The source and target shares must be in the same storage account. The sample creates the target share if it doesn't exist.

## Authentication and permissions

The sample reads the connection string from the `AZURE_STORAGE_CONNECTION_STRING` environment variable. With Shared Key authorization:

- The change feed client reuses the account key for both the file endpoint (to discover the share's `$fileschangefeed-<GUID>` container through Get Share Properties) and the blob endpoint (to read the change feed log). No role assignments are needed.
- Copy File authorizes the source with the destination request's Shared Key, which works because both shares are in the same account.

Keep the connection string out of source code and source control. If the storage account uses firewall rules or private endpoints, make sure the machine that runs the sample can reach both the file and blob endpoints.

## Run the sample

```powershell
cd ChangeFeedIncrementalCopy

# Optional: run the offline checks (no Azure access needed).
dotnet run -- self-test

$env:AZURE_STORAGE_CONNECTION_STRING = "<connection-string>"
dotnet run -- run --source-share <source-share> --target-share <target-share>
```

```bash
cd ChangeFeedIncrementalCopy
dotnet run -- self-test

export AZURE_STORAGE_CONNECTION_STRING="<connection-string>"
dotnet run -- run --source-share <source-share> --target-share <target-share>
```

Options:

| Option | Description | Default |
| --- | --- | --- |
| `--source-share` | Share with change feed enabled. The sample writes test data to a new folder in this share. | Required |
| `--target-share` | Share that receives the copies. Created if it doesn't exist. | Required |
| `--file-count` | Number of 8-KiB test files. Must be from 40 through 100,000 and divisible by 40, so the change set is exactly 10%. | `1000` |
| `--results` | Folder for the job checkpoint (`.json`) and the request summary (`.csv`). | `./results` |

A run usually takes several minutes. Most of that time is spent waiting for the service to finalize snapshot B in the change feed.

### Resume a job

The job state is saved to `<results>/<job-id>.json` after every phase. If a run is interrupted, or if the snapshots aren't finalized within 25 minutes, resume it without repeating completed work:

```powershell
dotnet run -- resume --job ./results/<job-id>.json
```

## What gets created

Each run uses a unique job ID, `cfcopy-<timestamp>-<guid>`:

```text
<source-share>/<job-id>/group-00 ... group-09                  test files
<target-share>/<job-id>/scan/group-00 ... group-09             copy driven by the full scan
<target-share>/<job-id>/changefeed/group-00 ... group-09       copy driven by change feed
```

The sample also creates **two snapshots of the entire source share**. The sample doesn't modify anything outside its job folders, and it never deletes data or snapshots on its own.

## Understand the results

When a run completes, the sample prints a per-phase summary and writes it to `<job-id>.csv`:

| Column | Meaning |
| --- | --- |
| `Phase` | Step of the job. See the following table. |
| `List` | `GET ...?comp=list` requests, including every continuation page. |
| `Read` | Other `GET` and `HEAD` requests, such as Get Properties and blob reads. |
| `Write` | `PUT`, `POST`, and `DELETE` requests, including Copy File. |
| `Other` | Requests with any other HTTP method. |
| `Total` | All requests in the phase. |
| `Seconds` | Elapsed time for the phase. |

To compare the two methods, use these phases:

| Phase | What it measures |
| --- | --- |
| `scan.detection` | Full scan of snapshot B: List Directories and Files plus Get File Properties for every file. |
| `feed.detection` | Change feed blob reads between snapshots A and B, plus Get File Properties for affected files only. |
| `scan.copy`, `feed.copy` | Applying the plan. Both methods produce the same plan, so these phases should be similar. |
| `feed.finalization-poll` | Time and requests spent waiting for both snapshots to be finalized in the change feed. |

The `setup.*`, `baseline.*`, and `validation.*` phases are reported separately and aren't part of either detection method.

The full scan reads the properties of every file, so its cost grows with the size of the namespace. Change feed detection grows with the number of changes. The change feed method also waits for the service to finalize the log, which adds latency to an immediate, one-time run. A recurring job can amortize that wait by processing changes up to the most recent finalized point.

The counts are HTTP requests observed by this client, including SDK retries. They aren't the transaction counts on your bill, and they don't include work that the service does internally, such as reading the source during a server-side copy. For billing information, see [Understand Azure Files billing](https://learn.microsoft.com/azure/storage/files/understanding-billing).

## How the change feed detection works

1. `GetSnapshotStatusAsync` is polled until both snapshots are `Finalized` in the change feed.
2. `GetChangesBetweenSnapshotsAsync(snapshotA, snapshotB)` returns the events recorded between the two snapshots. `ControlEvent` records are ignored.
3. Each event is matched to the job folder by path. Some events, such as `SmbExtend`, carry only a file ID, so the sample also resolves the file ID through the baseline index from snapshot A.
4. For a rename, both the old and new paths are marked as affected.
5. The sample gets the properties of each affected path in snapshot B. A missing file means it was deleted or renamed away. The resulting index is compared with the baseline to build the copy plan.

## Limitations

- The sample is a controlled demonstration, not a replication tool. It works on its own synthetic folder and expects no other process to modify that folder during the run.
- Directory changes (for example, creating, renaming, or deleting folders) inside the job folder aren't handled, and the job fails if it finds one.
- Changed files are copied in full. Byte-range (delta) copies aren't implemented.
- A rename is copied as a new file plus a delete of the old path, in both methods.
- The batched `GetChangesBetweenSnapshotsAsync` API throws if the change feed was reset between the snapshots. A production consumer should handle resets by re-establishing a baseline. See [Handle reset events](https://learn.microsoft.com/azure/storage/files/storage-files-change-feed#handle-reset-events).
- A production consumer that processes the feed continuously should persist continuation tokens and tolerate unknown reason codes and fields.
- Snapshots and test data are kept so that you can inspect the results. Snapshots of the source share can incur storage charges.

## Clean up

Delete the job folder from the source and target shares, and delete the two snapshots listed in the job file (`SnapshotA` and `SnapshotB`), or delete the shares if you created them only for this sample.
