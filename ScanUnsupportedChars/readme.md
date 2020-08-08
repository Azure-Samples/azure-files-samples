# ScanUnsupportedChars script for Azure File Sync

Use the ScanUnsupportedChars script to identify and rename files which contain unsupported characters that are not currently supported by Azure File Sync. 

## How to download the PowerShell script

- Go to: https://github.com/Azure-Samples/azure-files-samples
- Click **Code** and then click **Download ZIP.**
- Open the **azure-files-samples-master.zip** file and the script is located in the **ScanUnsupportedChars** directory.

## How to run the PowerShell script

**Note:** To run the ScanUnsupportedChars script, launch PowerShell as an administrator.

### How to identify files with invalid characters

```powershell
  <path to script>\ScanUnsupportedChars.ps1 -SharePath <share path> | Out-File -FilePath c:\script\output.txt
```

  **Example**
  ```powershell
  c:\script\ScanUnsupportedChars.ps1 -SharePath \\testshare.file.core.windows.net\filesharename| Out-File -FilePath c:\script\output.txt
  ```

### How to identify and rename files with invalid characters
```powershell
<path to script>\ScanUnsupportedChars.ps1 -SharePath <share path> -RenameItem -ReplacementString <string> | Out-File -FilePath c:\script\output.txt
```

  **Example to rename the files and replace the invalid character with a hyphen**
  ```powershell
  c:\script\ScanUnsupportedChars.ps1 -SharePath \\testshare.file.core.windows.net\filesharename -RenameItem -ReplacementString "-" | Out-File -FilePath c:\script\output.txt
  ```

**Note**: The -SharePath can be a local path (if the share is mounted on the server or using Azure File Sync) or a network path. See additional examples provided in the script.
