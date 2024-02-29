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
1. Determine the SDDL string for the desired permissions. If you have a file or folder that already has the desired permissions, you can use the following PowerShell command to get its SDDL string:

   ```powershell
   $sddl = (Get-Acl -Path "<path-to-file-or-folder>").Sddl
   ```
1. Define how to connect your storage account with storage account key:

   ```powershell
   $AccountName = "<storage-account-name>"
   $AccountKey = "<storage-account-key>"

   $context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
   ```

   If your storage account is on another Azure environment than the public Azure cloud, you can use the `-Environment` or `-FileEndpoint` flags of `New-AzStorageContext` to configure the address at which the storage account is reachable. See the documentation of [New-AzStorageContext](https://learn.microsoft.com/en-us/powershell/module/az.storage/new-azstoragecontext).
   
1. Call `Set-AzureFilesAclRecursive` as follows:

   ```powershell
   $FileShareName = "<file-share-name>"
   $sddl = "<sddl-string>"
   
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
