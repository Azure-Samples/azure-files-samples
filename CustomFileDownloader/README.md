# CustomFileDownloader

A .NET console tool for downloading files from Azure File shares. It is especially useful when some files may have invalid content that causes standard download requests to fail. The tool supports concurrent downloads and works with both connection strings and SAS tokens.

## Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) or later
- Access to an Azure Storage account with an Azure File share

## Build

```bash
dotnet build CustomFileDownloader.sln
```

## Usage

### Windows

```
CustomFileDownloader.exe <parameters>
```

### Linux / macOS

```
dotnet CustomFileDownloader <parameters>
```

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `shareName` | Required (with connection string) | | Name of the Azure File share |
| `shareUri` | Required (with SAS) | | Full URI of the Azure File share |
| `connectionString` | Required (if not using SAS) | | Azure Storage connection string |
| `sas` | Required (if not using connection string) | | SAS token for the share |
| `sourcePath` | Optional | `""` (root) | Path within the share to download from |
| `isSourceADirectory` | Optional | `true` | Set to `false` to download a single file |
| `downloadPath` | Optional | `""` (current directory) | Local path where files will be saved |
| `threadCount` | Optional | `64` | Number of concurrent download threads |

> **Note:** You must provide either `shareName` + `connectionString`, or `shareUri` + `sas`.

## Examples

### Download a directory using a connection string (Windows)

```
CustomFileDownloader.exe shareName:yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true connectionString:AccountName=sourceaccountname;AccountKey=XXXXXXXXXXXX;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https; threadCount:64
```

### Download a directory using a SAS token (Windows)

```
CustomFileDownloader.exe shareUri:https://sourceaccountname.file.core.windows.net/yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true sas:XXXXXXXXXXXXXXXXXXX threadCount:64
```

### Download a directory using a connection string (Linux)

```
dotnet CustomFileDownloader shareName:yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true connectionString:AccountName=sourceaccountname;AccountKey=XXXXXXXXXXXX;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https; downloadPath:/home/yourpath threadCount:64
```

### Download a directory using a SAS token (Linux)

```
dotnet CustomFileDownloader shareUri:https://sourceaccountname.file.core.windows.net/yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true sas:XXXXXXXXXXXXXXXXXXX threadCount:64
```

### Download a single file

```
CustomFileDownloader.exe shareName:yourshare sourcePath:DirInFileShare1/myfile.txt isSourceADirectory:false connectionString:AccountName=sourceaccountname;AccountKey=XXXXXXXXXXXX;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https;
```

## How It Works

1. **List phase** — The tool enumerates all files and directories under `sourcePath`, recursively creating the local directory structure.
2. **Download phase** — Files are added to a concurrent queue and downloaded in parallel, bounded by `threadCount`.
3. Errors on individual files are logged and skipped so the remaining downloads can continue.
