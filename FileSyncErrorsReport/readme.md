# FileSyncErrorsReport script for Azure File Sync

Use the FileSyncErrorsReport script to parse Azure File Sync error log and then list the items currently not syncing properly. The result of the script is a table that shows all per-item errors. The table can be grouped by SyncGroup this server participates in.

## How to download the PowerShell script

- Go to: https://github.com/Azure-Samples/azure-files-samples
- Click **Code** and then click **Download ZIP.**
- Open the **azure-files-samples-master.zip** file and the script is located in the **FileSyncErrorsReport** directory.

## How to run the PowerShell script

To run the FileSyncErrorsReport script:
- Launch PowerShell as an administrator.
- Copy FileSyncErrorsReport.ps1 under $Env:ProgramFiles\Azure\StorageSyncAgent

**Note:** Script usage:
- To see the examples:
```powershell
    get-help $Env:ProgramFiles\Azure\StorageSyncAgent\FileSyncErrorsReport.ps1 -example
```
- For more information:
```powershell
    get-help $Env:ProgramFiles\Azure\StorageSyncAgent\FileSyncErrorsReport.ps1 -detailed
```

### How to get a report that include all sync sessions and all errors
```powershell
    $Env:ProgramFiles\FileSyncErrorsReport.ps1 -ReportAllErrors
```
### How to get a report for a given sync group
```powershell
    $Env:ProgramFiles\FileSyncErrorsReport.ps1 -SyncGroupName 'sync group name'
```

### How to get a report for a given sync group and output the report to a CSV file
```powershell
    $Env:ProgramFiles\FileSyncErrorsReport.ps1 -SyncGroupName 'sync group name'  -CsvPath 'output_path.CSV'
```
