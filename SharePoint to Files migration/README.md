# SharePoint Online to Azure Files Copy Tool

A comprehensive tool (available in **PowerShell** and **Python**) that **copies** files and folders from SharePoint Online document libraries to Azure Files. **Source data is never deleted** — your SharePoint library remains completely intact.

Key capabilities:
- **Parallel downloads** for high performance (100+ GiB copies)
- **AzCopy integration** for bulk uploads (10-100× faster)
- **Rich terminal UI** with real-time progress tracking
- **Checkpoint/resume** for interrupted migrations
- **Change detection** — skips unchanged files, re-uploads modified ones
- **Overwrite mode** — force re-upload of all files regardless of checkpoint
- **Permission export** with Entra ID SID mapping
- **NTFS ACL application** using Entra ID Kerberos authentication

## 🚀 Which Version Should I Use?

| Feature | PowerShell | Python (Recommended) |
|---------|------------|----------------------|
| **Download Speed** | ~10 MB/s (sequential) | **~50 MB/s** (8 parallel workers) |
| **Upload Speed** | ~20 MB/s (SDK) | **~300 MB/s** (AzCopy) |
| **Resume Support** | ❌ No | ✅ Checkpoint file |
| **Progress UI** | Basic console | ✅ Rich TUI with speeds |
| **Best For** | Small migrations (<10 GB) | **Large migrations (100+ GB)** |

## ⚠️ Important: Feature Limitations

**Before copying, understand that Azure Files is a file storage service, NOT a document management system.**

### What This Script Does

| Capability | Description |
|------------|-------------|
| ✅ **File Copy** | Copies all files from a SharePoint document library to Azure Files (source is NOT deleted) |
| ✅ **Directory Structure** | Preserves the complete folder hierarchy |
| ✅ **Permission Export** | Exports SharePoint M365 Group permissions and applies NTFS ACLs via Win32 API |
| ✅ **Entra ID Kerberos** | Supports cloud-only identity-based authentication on the storage account |
| ✅ **NTFS ACLs** | Applies raw SID ACLs without requiring name resolution (works on any Windows machine) |
| ✅ **Progress Tracking** | Detailed logging with file-level progress and retry logic |
| ✅ **Delta Query** | Efficiently enumerates large libraries using Graph API delta queries |
| ✅ **Token Refresh** | Automatic token refresh for long-running migrations (>45 minutes) |
| ✅ **Retry Mechanism** | Automatic retry of failed files with fresh tokens |
| ✅ **Change Detection** | Compares SharePoint `lastModifiedDateTime` against checkpoint — only re-uploads files modified since last run |
| ✅ **Overwrite Mode** | `--overwrite` flag forces re-copy of all files, ignoring the checkpoint |

### What SharePoint Features You Will LOSE

| Feature | Impact | Workaround |
|---------|--------|------------|
| 🚫 **Version History** | Only the latest version is migrated; all previous versions are lost | Export versions manually before migration |
| 🚫 **Metadata & Custom Columns** | SharePoint metadata, content types, and custom columns are NOT migrated | Export metadata to a separate CSV/JSON file |
| 🚫 **Sharing Links** | External/internal sharing links are not preserved | Reconfigure access via Azure Files RBAC or NTFS ACLs |
| 🚫 **Co-authoring** | Real-time collaboration (Office for the web) not available in Azure Files | Use SharePoint/OneDrive for collaborative editing |
| 🚫 **Power Automate Flows** | Workflows and automation don't migrate | Recreate flows using Azure Logic Apps or Power Automate with Azure connectors |
| 🚫 **Comments & Annotations** | File comments and annotations are lost | Export comments manually if needed |
| 🚫 **Check-in/Check-out** | Document check-out functionality not available | Use file locking at the SMB level |
| 🚫 **Content Approval** | Approval workflows are not migrated | Implement approval via other means |
| 🚫 **Alerts & Notifications** | Email alerts on file changes not migrated | Use Azure Event Grid for file change notifications |
| 🚫 **Retention Policies** | SharePoint retention labels/policies don't apply | Configure Azure Blob/Files lifecycle management |
| 🚫 **eDiscovery & Compliance** | Microsoft 365 compliance features not available | Use Azure compliance solutions |
| 🚫 **Search Integration** | SharePoint search index not available | Use Azure Cognitive Search if needed |
| 🚫 **OneNote Notebooks** | OneNote files (.one) may not work properly outside SharePoint | Keep notebooks in SharePoint/OneDrive |
| 🚫 **SharePoint Pages/Sites** | Site pages, web parts, and site structure not migrated | This script only migrates document library content |
| 🚫 **Lists** | SharePoint lists are not migrated | Export lists separately or use different tools |

### Who Should Use This Script

✅ **Good Fit:**
- Archiving old SharePoint content to cheaper storage
- Migrating file-centric content that doesn't need collaboration features
- Organizations moving away from SharePoint for file storage
- Backup/disaster recovery copies

❌ **Not Recommended:**
- Active collaboration environments
- Documents requiring version control
- Content with complex metadata or workflows
- Regulatory compliance scenarios requiring SharePoint features

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Migration Flow                               │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────┐    Microsoft Graph API    ┌──────────────────────┐
│   SharePoint     │ ──────────────────────── │   PowerShell Script   │
│   Online         │   (Delta Query + Download)│                      │
│                  │                           │  • Token Management  │
│  ┌────────────┐  │                           │  • Retry Logic       │
│  │ Documents  │  │                           │  • Progress Tracking │
│  │ Library    │  │                           │                      │
│  └────────────┘  │                           └──────────┬───────────┘
└──────────────────┘                                      │
                                                          │ Az.Storage Module
                                                          │ (REST API)
                                                          ▼
                                              ┌──────────────────────┐
                                              │   Azure Files        │
                                              │                      │
                                              │  ┌────────────────┐  │
                                              │  │ File Share     │  │
                                              │  │ (SMB 3.0)      │  │
                                              │  └────────────────┘  │
                                              │                      │
                                              │  • Entra ID Kerberos │
                                              │  • NTFS ACLs         │
                                              └──────────────────────┘
```

## Prerequisites

### Required Software

| Software | Version | Installation |
|----------|---------|--------------|
| **PowerShell** | 7.0+ | `winget install Microsoft.PowerShell` |
| **Azure CLI** | Latest | `winget install Microsoft.AzureCLI` |
| **Az.Storage Module** | Latest | `Install-Module Az.Storage -Force` |

### Required Permissions

| Service | Permission | Purpose |
|---------|------------|---------|
| Microsoft Graph | `Sites.Read.All` | Read SharePoint site structure |
| Microsoft Graph | `Files.Read.All` | Download files from document libraries |
| Microsoft Graph | `Group.Read.All` | Read group membership for permission export |
| Azure Storage | `Storage Account Key` or `Storage Blob Data Contributor` | Upload files to Azure Files |
| Azure Storage | `Contributor` on Storage Account | Enable Entra ID Kerberos (optional) |

### Azure Resources Setup

1. **Create Storage Account** (if not exists):
   ```bash
   az storage account create \
       --name mystorageaccount \
       --resource-group my-rg \
       --location eastus \
       --sku Standard_LRS \
       --kind StorageV2
   ```

2. **Create File Share**:
   ```bash
   az storage share create \
       --name myfileshare \
       --account-name mystorageaccount \
       --quota 100
   ```

3. **Enable Entra ID Kerberos** (optional, for identity-based access):
   ```bash
   az storage account update \
       --name mystorageaccount \
       --resource-group my-rg \
       --enable-files-aadkerb true
   ```

## Quick Start

### Step 1: Login to Azure

```powershell
az login
```

### Step 2a: Python Migration (Recommended for Large Migrations)

```bash
# Install dependencies
pip install -r requirements.txt

# Interactive wizard
python migrate_sp_to_azure_files.py --interactive

# Or command line
python migrate_sp_to_azure_files.py \
    --site-url "https://contoso.sharepoint.com/sites/mysite" \
    --library "Documents" \
    --storage-account "mystorageaccount" \
    --file-share "myfiles" \
    --resource-group "my-rg" \
    --subscription "my-subscription"

# Force re-upload all files (ignore checkpoint)
python migrate_sp_to_azure_files.py \
    --site-url "https://contoso.sharepoint.com/sites/mysite" \
    --library "Documents" \
    --storage-account "mystorageaccount" \
    --file-share "myfiles" \
    --resource-group "my-rg" \
    --subscription "my-subscription" \
    --overwrite
```

### Step 2b: PowerShell Migration (Files Only)

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription"
```

### Step 3: Verify Migration

```powershell
# Mount the share and verify
net use Z: \\mystorageaccount.file.core.windows.net\myfiles /user:AZURE\mystorageaccount <storage-key>
dir Z:\
```

## Usage Examples

### Test Run (First 5 Files)

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription" `
    -MaxFiles 5
```

### Full Migration with Permission Export

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription" `
    -ExportPermissions
```

### Full Migration with NTFS ACL Application

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription" `
    -ExportPermissions `
    -EnableEntraKerberos `
    -ApplyNtfsAcls `
    -MountDriveLetter "Z"
```

> **Note**: NTFS ACL application via icacls requires an **Entra ID-joined Windows device** to resolve Azure AD SIDs. If running on a non-joined device, use share-level RBAC instead.

### Preview Mode (What-If)

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription" `
    -WhatIf
```

### Migrate to Subfolder

```powershell
.\Migrate-SharePointToAzureFiles.ps1 `
    -SharePointSiteUrl "https://contoso.sharepoint.com/sites/mysite" `
    -DocumentLibraryName "Documents" `
    -StorageAccountName "mystorageaccount" `
    -FileShareName "myfiles" `
    -ResourceGroup "my-rg" `
    -Subscription "my-subscription" `
    -TargetFolder "Archive/2024"
```

## Parameters Reference

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `SharePointSiteUrl` | Yes | - | Full URL of the SharePoint site (e.g., `https://contoso.sharepoint.com/sites/mysite`) |
| `DocumentLibraryName` | Yes | - | Name of the document library to migrate (e.g., "Documents", "Shared Documents") |
| `StorageAccountName` | Yes | - | Azure Storage account name |
| `FileShareName` | Yes | - | Azure Files share name |
| `ResourceGroup` | Yes | - | Resource group containing the storage account |
| `Subscription` | Yes | - | Azure subscription ID or name |
| `TargetFolder` | No | (root) | Subfolder in Azure Files for migrated content |
| `MaxFiles` | No | 0 (all) | Limit migration to N files (for testing) |
| `ExportPermissions` | No | False | Export SharePoint permissions with SID mapping |
| `EnableEntraKerberos` | No | False | Enable Entra ID Kerberos on storage account |
| `ApplyNtfsAcls` | No | False | Apply NTFS ACLs to migrated files |
| `MountDriveLetter` | No | - | Drive letter for mounting (required with `-ApplyNtfsAcls`) |
| `PermissionsOutputFile` | No | SharePointPermissions.json | Path for permissions JSON output |
| `WhatIf` | No | False | Preview mode - show what would be migrated |

### Python CLI Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--site-url` | Yes | - | SharePoint site URL |
| `--library` | Yes | - | Document library name |
| `--storage-account` | Yes | - | Azure Storage account name |
| `--file-share` | Yes | - | Azure Files share name |
| `--resource-group` | Yes | - | Resource group containing the storage account |
| `--subscription` | Yes | - | Azure subscription ID or name |
| `--target-folder` | No | (root) | Subfolder in Azure Files for migrated content |
| `--max-files` | No | 0 (all) | Limit migration to N files (for testing) |
| `--export-permissions` | No | False | Export SharePoint permissions with SID mapping |
| `--concurrent-downloads` | No | 8 | Number of parallel download workers |
| `--temp-dir` | No | (auto) | Temporary directory for downloads |
| `--checkpoint-file` | No | `logs/checkpoint.json` | Checkpoint file for resume support |
| `--dry-run` | No | False | Preview mode — show what would be migrated |
| `--overwrite` | No | False | Overwrite target files even if source is unchanged. Ignores checkpoint and re-uploads all files |
| `--interactive` / `-i` | No | False | Run interactive configuration wizard |

## Permission Mapping

SharePoint permissions are translated to NTFS permissions as follows:

| SharePoint Role | NTFS Permission | icacls Code |
|-----------------|-----------------|-------------|
| Owner / Full Control | FullControl | `(OI)(CI)F` |
| Edit / Contribute / Write | Modify | `(OI)(CI)M` |
| Read | ReadAndExecute | `(OI)(CI)RX` |
| View Only | Read | `(OI)(CI)R` |

### Entra ID SID Format

Azure AD Object IDs (GUIDs) are converted to Windows SIDs using the format:
```
S-1-12-1-{GUID bytes as 4 x 32-bit unsigned integers}
```

Example:
- Object ID: `e8f8bb47-fd46-dd46-171b-b3bfcd206d0d`
- SID: `S-1-12-1-3888643736-1189937757-387532977-1831556275`

This enables cloud-only authentication without requiring on-premises AD DS.

### NTFS ACL Application Requirements

To successfully apply NTFS ACLs with Azure AD SIDs:

1. **Option A: Entra-Joined Device** - Run the script from a Windows device that is Entra ID (Azure AD) joined
2. **Option B: Share-Level RBAC** - Use Azure RBAC roles instead of NTFS ACLs:
   - `Storage File Data SMB Share Reader` - Read access
   - `Storage File Data SMB Share Contributor` - Read/Write access
   - `Storage File Data SMB Share Elevated Contributor` - Read/Write/Modify NTFS ACLs

## Output Files

| File | Description |
|------|-------------|
| `Migration_YYYYMMDD_HHMMSS.log` | Detailed migration log with timestamps |
| `SharePointPermissions.json` | Exported permissions with SID mapping |
| `FailedFiles_YYYYMMDD_HHMMSS.json` | List of files that failed after all retries |

### Sample Permissions JSON

```json
{
  "SiteUrl": "https://contoso.sharepoint.com/sites/mysite",
  "SiteName": "MySite",
  "ExportDate": "2024-01-23 14:30:00",
  "Permissions": [
    {
      "Path": "/",
      "Principal": "MySite Owners",
      "PrincipalType": "Group",
      "ObjectId": "e8f8bb47-fd46-dd46-171b-b3bfcd206d0d",
      "SID": "S-1-12-1-3888643736-1189937757-387532977-1831556275",
      "SharePointRole": "Owner",
      "NtfsPermission": "FullControl"
    }
  ]
}
```

## Authentication

This script uses **Azure CLI tokens** for authentication, which works without additional admin consent in most environments.

### Authentication Flow

```
1. az login                           # User authenticates to Azure
2. Script calls: az account get-access-token --resource "https://graph.microsoft.com"
3. Token is used for all Graph API calls
4. Token auto-refreshes every 45 minutes (before 60-min expiry)
5. Storage account key is used for Azure Files operations
```

### Why Azure CLI Tokens?

| Advantage | Description |
|-----------|-------------|
| No App Registration | Works with user's existing Azure CLI session |
| No Admin Consent | Delegated permissions via user identity |
| Automatic Refresh | Script handles token refresh for long migrations |
| Multi-tenant Support | Works across different tenants |

## Performance Considerations

### Current Limitations

- **Sequential Downloads**: Files are downloaded one at a time
- **Memory Usage**: Each file is downloaded to temp directory before upload
- **Network Dependency**: Speed limited by network to SharePoint and Azure

### Estimated Migration Times

| File Count | Avg File Size | PowerShell (Sequential) | Python (Parallel + AzCopy) |
|------------|---------------|-------------------------|----------------------------|
| 100 | 1 MB | ~5 minutes | ~1 minute |
| 1,000 | 5 MB | ~60-90 minutes | ~10-15 minutes |
| 10,000 | 5 MB | ~10-15 hours | ~1-2 hours |

### Performance Tips

- Use `--concurrent-downloads 16` for higher download throughput on fast networks
- AzCopy concurrency is set to 64 by default (configurable via `AZCOPY_CONCURRENCY` constant)
- The `--overwrite` flag skips checkpoint comparison, which can be slightly faster for fresh migrations
- Storage account key and SAS token are cached across batches to avoid repeated Azure CLI calls

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `Failed to get Graph token` | Not logged in to Azure CLI | Run `az login` first |
| `Library not found` | Incorrect library name | Check exact library name (use display name, not URL path) |
| `Failed to get storage account key` | Wrong subscription/RG or no permissions | Verify subscription, resource group, and RBAC permissions |
| `401 Unauthorized` during migration | Token expired | Script auto-retries with fresh token |
| `No mapping between account names and security IDs` | Not running on Entra-joined device | Use share-level RBAC instead of NTFS ACLs |
| `Access denied on mount` | Storage firewall blocking | Add your IP to storage account firewall |

### Debug Mode

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
.\Migrate-SharePointToAzureFiles.ps1 ...
```

### Check Azure CLI Login

```powershell
az account show
az account get-access-token --resource "https://graph.microsoft.com" --query "expiresOn"
```

## Post-Migration Checklist

- [ ] **Verify file count** - Compare source and destination file counts
- [ ] **Spot check files** - Open random files to verify integrity
- [ ] **Test SMB access** - Mount share from client machines
- [ ] **Configure RBAC** - Assign appropriate Azure RBAC roles
- [ ] **Set up backup** - Enable Azure Backup for file shares
- [ ] **Configure monitoring** - Set up Azure Monitor alerts
- [ ] **Update documentation** - Provide users with new access instructions
- [ ] **Plan decommission** - Schedule SharePoint site archival/deletion

## Security Considerations

1. **Storage Account Keys** - Script uses storage account keys; consider using Managed Identity in production
2. **Temporary Files** - Files are temporarily stored in `%TEMP%`; ensure adequate disk space
3. **Credentials in Memory** - Tokens are stored in script variables; cleared on script completion
4. **Network Traffic** - All traffic uses HTTPS (Graph API) and SMB 3.0 with encryption

## Contributing

Contributions are welcome! Please see the TODO comments in the script for areas needing improvement.

## License

Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the [MIT License](https://opensource.org/licenses/MIT).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

**Disclaimer**: This code is provided "as is" without warranty of any kind, express or implied. Test thoroughly in a non-production environment before production use.

## Author

**Shekhar Sorot** - [shsorot@microsoft.com](mailto:shsorot@microsoft.com)

## Support

This is a community script provided as-is. For enterprise migrations, consider:
- [Microsoft SharePoint Migration Tool (SPMT)](https://docs.microsoft.com/sharepoint/migrate-to-sharepoint-online)
- [Azure File Sync](https://docs.microsoft.com/azure/storage/file-sync/file-sync-introduction)
- Third-party migration tools (Sharegate, AvePoint, etc.)
