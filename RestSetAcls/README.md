# RestSetAcls.psm1

## Description

RestSetAcls.psm1 is a PowerShell module that provides functions to set Access Control Lists (ACLs) for Azure file shares, using the Azure Files REST API.

## Prerequisites

- PowerShell 5.1 or later
- `Az.Storage` module v4.1.1 or later
- Azure Storage account
- Azure Storage account key

## Installation

1. Download the `RestSetAcls.psm1` file from this repo.
2. Save the file to a local directory.

## Usage

1. Open a PowerShell session.
2. Call `Set-AzureFilesAclRecursive` as follows:

   ```powershell  
   $AccountName = "<storage-account-name>"
   $FileShareName = "<file-share-name>"
   $AccountKey = "<storage-account-key>"
   $sddl = "<sddl-string>"
    
   $context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
   
   Import-Module -Name "Path\To\RestSetAcls.psm1"
   Set-AzureFilesAclRecursive -Context $context -FileShareName $FileShareName -FilePath "/" -SddlPermission $sddl
   ```

## Testing

1. Mount the file share to a local drive

   ```cmd
   net use X: \\<storage-account-name>.file.core.windows.net\<file-share-name> /u:<storage-account-name> <storage-account-key>
   ```

2. Create test files

    ```powershell
    .\RestSetAcls\TestSetup.ps1
    ```

3. Try to set permissions via icacls

    ```cmd
    icacls X:\ /t /grant "Everyone:(OI)(CI)F"
    ```

4. Compare the speed of this operation to the `Set-AzureFilesAclRecursive` function

    ```powershell
    Set-AzureFilesAclRecursive -Context $context -FileShareName $FileShareName -FilePath "/" -SddlPermission $sddl
    ```
