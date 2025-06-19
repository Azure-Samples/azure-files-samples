# RestSetAcls.psm1

## Description

RestSetAcls.psm1 is a PowerShell module that provides functions to set Access Control Lists (ACLs) for Azure file shares, using the Azure Files REST API.

> [!NOTE]  
> RestSetAcls.psm1 currently only supports setting the same owner, group and permissions on all files within a share or subdirectory.
> It does not yet support:
>
> - Updates to one field without updating others (e.g., updating the owner without updating the group and permissions)
> - Adding or removing a permission, without otherwise changing the permissions

## Prerequisites

- PowerShell 5.1 or later. For the best performance, PowerShell 7+ is recommended ([installation instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- `Az.Storage` module v4.1.1 or later ([installation instructions](https://learn.microsoft.com/en-us/powershell/azure/install-azure-powershell))
- Azure Storage account with a file share
- Azure Storage account key ([instructions on how to find the key](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#view-account-access-keys))

## Installation

```powershell
Install-Module RestSetAcls
```

## Usage

1. Make sure you meet the prerequisites above.
1. Open a PowerShell session. PowerShell 7 is preferred, but PowerShell 5 (aka Windows PowerShell) is also acceptable.
1. Define how to connect your storage account with storage account key:

   ```powershell
   $AccountName = "<storage-account-name>" # replace with the storage account name
   $AccountKey = "<storage-account-key>" # replace with the storage account key

   $context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
   ```

   If your storage account is on another Azure environment than the public Azure cloud, you can use the `-Environment` or `-FileEndpoint` flags of `New-AzStorageContext` to configure the address at which the storage account is reachable. See the documentation of [New-AzStorageContext](https://learn.microsoft.com/en-us/powershell/module/az.storage/new-azstoragecontext).
   
1. Determine the SDDL string for the desired permissions.

   If you already know what SDDL string you want, you can define it directly:

   ```powershell
   $sddl = "<sddl-string>" # replace with the SDDL string
   ```

   If you do not know the SDDL string for the permission you want to set, the easiest approach is to get it from another file. In other words, the idea is to use the permissions of another file as a template of what permissions should be set recursively on your file share. To do so, we either need a file that has the right permissions already, or we need to create it. To create it, you can create a file (anywhere you want, for instance on your Desktop), right click on it, click on Properties, go to the Security tab, click Edit, and then add, remove or edit permissions until you get the permissions you want. Press OK to save and OK to close the Properties window. You can then get the SDDL of your sample file as follows:

   ```powershell
   $filepath = "<path-to-file-or-folder>" # replace with the path to your file or folder
   $sddl = (Get-Acl -Path $filepath).Sddl
   ```
   
1. Call `Set-AzFileAclRecursive` as follows. This will recursively find all files and folders on your file share, and set the SDDL permission on each one of them.

   ```powershell
   $FileShareName = "<file-share-name>" # replace with the name of your file share
   
   Set-AzFileAclRecursive -Context $context -FileShareName $FileShareName -FilePath "/" -SddlPermission $sddl
   ```

## Advanced usage

### Export CSV logs of changes made

You can export a CSV file that logs the changes made by `Set-AzFileAclRecursive`. This can be useful to keep track of the changes made, or to review them later.

To do this, use the `-PassThru` flag, and pass the output to `Export-Csv`:

```powershell
Set-AzFileAclRecursive `
   -Context $context `
   -FileShareName $FileShareName `
   -FilePath "/" `
   -SddlPermission $sddl `
   -PassThru `
   | Export-Csv -Path "C:\path\to\log.csv"
```

To customize the CSV output, see the documentation of [Export-Csv](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv).
