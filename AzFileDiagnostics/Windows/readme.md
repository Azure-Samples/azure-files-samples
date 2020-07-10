#  AzFileDiagnostics script for Windows

The AzFileDiagnostics script automates detection of most of the common symptoms mentioned in the [Azure Files troubleshooting guide](https://docs.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems) and mounts the file share on the client machine. 

## How to download the PowerShell script

- Go to: https://github.com/Azure-Samples/azure-files-samples
- Click **Code** and then click **Download ZIP.**
- Open the **azure-files-samples-master.zip** file and the script is located in the **AzFileDiagnostics\Windows** directory.

## How to run the PowerShell script

**Note:** To run the AzFileDiagnostics script, launch PowerShell as an administrator. 

The script can run without any parameter and it will perform basic validations without needing storage account information:

```powershell
.\AzFileDiagnostics.ps1
```

Alternatively, you can specify optional parameters when running the script if you wish to perform validations against a specific storage account:

Example 1:

```powershell
.\AzFileDiagnostics.ps1 -UNCPath \\storageaccountname.file.core.windows.net\sharename
```

 Example 2:

```powershell
.\AzFileDiagnostics.ps1 -StorageAccountName <name> -FileShareName <name> -Environmentname AzureCloud
```

_NOTE: Environmentname specifies the Azure environment. Valid values are: AzureCloud, AzureChinaCloud, AzureUSGovernment. The default is AzureCloud._

## Parameters

| Parameter | Description |
|-|-|
| -UNCPath | Azure File share UNC path like storageaccount.file.core.windows.net\sharename. |
| -StorageAccountName | Storage Account name where the Azure file share is located. Script will validate the storage naming convention. |
| -FileShareName | Specify the file share name and script will validate the file share name convention. |
| -Environmentname | Specifies the Azure environment. Valid values are AzureCloud, AzureChinaCloud, AzureUSGovernment. The default is AzureCloud. |

## Validations Preformed

- OS version: Verify OS version is Windows 7, Windows Server 2008 R2 or later. 

- SMB version: Verify client supports SMB version 2.1 or 3.0.   

- Hotfix KB3114025: For Windows 8.1 or Windows Server 2012 R2 clients, verify hotfix KB3114025 is installed.

- NTLM: Verify LmCompatibilityLevel registy setting is set to a value of 3. NTLMv1 is not supported.

- Storage account: Verify the storage account name or UNC path exists.

- Azure VM: If client is using SMB 2.x, verify client is Azure VM in the same region as storage account.

- Port 445: When mounting the Azure file share, verify TCP port 445 is not blocked.

- Firewall: Verify local firewall rules are not blocking connectivity to Azure file share.

- If all validations pass, map the drive on behalf of the user. User can also choose turn on the diagnostics to collect more logs.

## Sample Output

  ![](./images/img1.png)

## Disclaimer

The sample scripts are not supported under any Microsoft standard support program or service. The sample scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
