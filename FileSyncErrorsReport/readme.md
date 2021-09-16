# FileSyncErrorsReport script for Azure File Sync

Use the FileSyncErrorsReport script to identify and rename files which contain unsupported characters that are not currently supported by Azure File Sync. 

## How to download the PowerShell script

- Go to: https://github.com/Azure-Samples/azure-files-samples
- Click **Code** and then click **Download ZIP.**
- Open the **azure-files-samples-master.zip** file and the script is located in the **FileSyncErrorsReport** directory.

## How to run the PowerShell script

**Note:** To run the FileSyncErrorsReport script, launch PowerShell as an administrator.
**Note:** Copy FileSyncErrorsReport.ps1 under $Env:ProgramFiles\Azure\StorageSyncAgent
**Note:** To see the examples, type: "get-help $Env:ProgramFiles\Azure\StorageSyncAgent\FileSyncErrorsReport.ps1 -examples".
**Note:** For more information, type: "get-help $Env:ProgramFiles\Azure\StorageSyncAgent\FileSyncErrorsReport.ps1 -detailed".
**Note:** For technical information, type: "get-help $Env:ProgramFiles\Azure\StorageSyncAgent\FileSyncErrorsReport.ps1 -full".

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

**Note**: The -SharePath can be a local path (if the share is mounted on the server or using Azure File Sync) or a network path. See additional examples provided in the script.