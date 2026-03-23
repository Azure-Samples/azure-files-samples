# SharePoint to Azure Files Copy Tool

A high-performance Python tool for **copying** files from SharePoint Online document libraries to Azure Files with parallel downloads, checkpoint/resume support, and a rich terminal UI.

> **Source data is never deleted** -- your SharePoint library remains completely intact.

## Features

- **Async Parallel Downloads** - 8 concurrent workers by default (configurable)
- **AzCopy Integration** - High-speed bulk uploads with 64 concurrent transfers
- **Rich Terminal UI** - Real-time progress with download/upload speeds
- **Checkpoint/Resume** - Automatically resumes interrupted copies
- **Permission Preservation** - Site-level M365 Group ACLs applied via Win32 API (no name resolution required)
- **Metadata Preservation** - Exports SharePoint metadata to `.sp-metadata.json` sidecar files
- **Timestamp Preservation** - Original created/modified dates preserved via SMB
- **Automatic Token Refresh** - Handles long-running copies seamlessly
- **Change Detection** - Only re-uploads files modified since the last run
- **Overwrite Mode** - Force re-upload of all files regardless of checkpoint

## What Gets Preserved

| SharePoint Property | Preserved? | Method |
|---------------------|:----------:|--------|
| File content | Yes | Copied to Azure Files |
| Directory structure | Yes | Preserved as-is |
| Created/Modified dates | Yes | SMB properties (`--preserve-smb-info`) |
| Site permissions (Owners/Members) | Yes | Win32 API raw SID ACLs + AzCopy `--preserve-smb-permissions` |
| Per-file unique permissions | Yes | Win32 API raw SID ACLs (for files with broken inheritance) |
| Custom columns (metadata) | Yes | `.sp-metadata.json` sidecar files |
| Content type | Yes | `.sp-metadata.json` sidecar files |
| File hashes | Yes | `.sp-metadata.json` + AzCopy `--put-md5` |
| Version history | **No** | Only latest version copied |
| Comments | **No** | Not available in Azure Files |
| Co-authoring | **No** | Not available in Azure Files |
| Sharing links | **No** | Must be reconfigured |

## How Permissions Work

SharePoint permissions are translated to NTFS ACLs and applied to the local temp files before AzCopy uploads them:

```
SharePoint M365 Group             NTFS ACL on Azure Files
----------------------------      ----------------------------
Group itself (Azure Files 2)  --> S-1-12-1-...: Modify (OI)(CI)
Group Owners (Ran, Will, ...)  --> S-1-12-1-...: FullControl (per-file)
Group Members (85 users)       --> S-1-12-1-...: Modify (per-file)
```

- **Site-level ACLs** are applied to the temp directory root with Object Inherit + Container Inherit flags. All files automatically inherit these.
- **Per-file unique ACLs** (broken SharePoint inheritance) are applied individually.
- Uses the **Win32 Security API** directly (not `icacls`) so SIDs don't need to be resolvable on the local machine.
- Requires `--export-permissions` flag and `--preserve-smb-permissions` (auto-enabled on Windows).

### Prerequisites for Permission Enforcement

1. Storage account must have **Entra ID Kerberos** identity-based authentication enabled
2. Users accessing the share must authenticate via **Entra ID Kerberos**
3. **Share-level RBAC** must also be configured (admin task, not automated)

## Performance

Typical throughput on a 1 Gbps connection:

| Phase | Speed | Method |
|-------|-------|--------|
| Download from SharePoint | ~50 MB/s | 8 parallel async workers |
| Upload to Azure Files | ~300 MB/s | AzCopy with 64 threads |
| End-to-end (100 GB library) | ~30 min | Batched pipeline |

## Prerequisites

### Required Software

1. **Python 3.10+**
   ```powershell
   python --version
   ```

2. **Azure CLI** - Installed and logged in
   ```powershell
   az login
   az account show
   ```

3. **AzCopy** - Installed and in PATH
   ```powershell
   azcopy --version
   ```
   Download: https://docs.microsoft.com/azure/storage/common/storage-use-azcopy-v10

### Python Dependencies

```powershell
cd python
pip install -r requirements.txt
```

## Usage

### Quick Start (Interactive)

```powershell
python migrate_sp_to_azure_files.py --interactive
```

### Command Line

```powershell
# Basic copy
python migrate_sp_to_azure_files.py ^
    --site-url "https://contoso.sharepoint.com/sites/mysite" ^
    --library "Documents" ^
    --storage-account "mystorageaccount" ^
    --file-share "myfiles" ^
    --resource-group "my-rg" ^
    --subscription "my-subscription-id"

# With permissions and custom target folder
python migrate_sp_to_azure_files.py ^
    --site-url "https://contoso.sharepoint.com/sites/mysite" ^
    --library "Documents" ^
    --storage-account "mystorageaccount" ^
    --file-share "myfiles" ^
    --resource-group "my-rg" ^
    --subscription "my-subscription-id" ^
    --export-permissions ^
    --target-folder "archive/2024"

# Dry run (see what would be copied)
python migrate_sp_to_azure_files.py ... --dry-run

# Test with 10 files first
python migrate_sp_to_azure_files.py ... --max-files 10

# Force re-upload everything
python migrate_sp_to_azure_files.py ... --overwrite
```

## Command Line Arguments

| Argument | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `--site-url` | Yes | -- | SharePoint site URL |
| `--library` | Yes | -- | Document library name (e.g., "Documents") |
| `--storage-account` | Yes | -- | Azure Storage account name |
| `--file-share` | Yes | -- | Azure Files share name |
| `--resource-group` | Yes | -- | Azure resource group |
| `--subscription` | Yes | -- | Azure subscription ID or name |
| `--interactive`, `-i` | No | -- | Run interactive configuration wizard |
| `--target-folder` | No | Library name | Subfolder in Azure Files (defaults to library name) |
| `--max-files` | No | 0 (all) | Limit number of files (for testing) |
| `--export-permissions` | No | False | Export and apply SharePoint permissions as NTFS ACLs |
| `--concurrent-downloads` | No | 8 | Number of parallel download workers |
| `--temp-dir` | No | System temp | Temporary directory for downloads |
| `--checkpoint-file` | No | logs/checkpoint.json | Checkpoint file for resume |
| `--dry-run` | No | False | Preview without copying |
| `--overwrite` | No | False | Ignore checkpoint, re-upload all files |

## Output Files

| File | Location | Description |
|------|----------|-------------|
| `.sp-metadata.json` | Each folder | Per-file metadata sidecar (permissions, timestamps, custom columns) |
| `SharePointPermissions.json` | Working directory | Site-level permissions export (when `--export-permissions` is used) |
| `logs/checkpoint.json` | Working directory | Resume checkpoint |
| `logs/migration_*.log` | logs/ | Detailed debug log |
| `logs/migration_perf_*.csv` | logs/ | Per-file performance metrics |

## Important Limitations

**Azure Files is a FILE STORAGE service, NOT a document management system.**

| Lost Feature | Impact |
|-------------|--------|
| Version History | Only latest version copied |
| Co-authoring | Not available in Azure Files |
| Sharing Links | Must be reconfigured |
| Power Automate | Must be recreated |
| Comments | Not preserved |
| Content Approval | Not available |
| Retention Policies | Must use Azure lifecycle management |
| eDiscovery | Must use Azure compliance tools |

**Good for:** Archiving, file-centric workloads, backup, hybrid cloud storage

**Not for:** Active collaboration, version control, compliance workflows

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `az.cmd not found` | Install Azure CLI: `winget install Microsoft.AzureCLI` |
| `azcopy not found` | Install AzCopy and add to PATH |
| Token expired | Run `az login` again |
| Slow downloads | Increase `--concurrent-downloads 16` |
| Permissions not applied | Add `--export-permissions` flag |
| Files skipped (already processed) | Use `--overwrite` to force re-upload |
| Unicode crash on Windows | Script auto-configures UTF-8 output |

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.

## Author

Shekhar Sorot (shsorot@microsoft.com)
