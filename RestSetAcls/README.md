# RestSetAcls

## Description

RestSetAcls is a PowerShell module that provides functions to set Access Control Lists (ACLs) for Azure file shares, using the Azure Files REST API. 

It's built as a wrapper of [Az.Storage](https://learn.microsoft.com/en-us/powershell/module/az.storage/?view=azps-15.0.0) and [Microsoft.Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-1.0) PowerShell modules, adding functionality for Azure Files ACLs on top of these.

## Prerequisites

- PowerShell 5.1 or later. For the best performance and experience, PowerShell 7+ is recommended ([installation instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- Azure Storage account with a file share
- Access to the [storage account's key](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal), or ability to [acquire an OAuth token](https://learn.microsoft.com/en-us/azure/storage/files/authorize-oauth-rest?tabs=portal) to the account

## Installation

```powershell
Install-Module RestSetAcls
```

This step will also install all dependencies, such as [Az.Storage](https://learn.microsoft.com/en-us/powershell/module/az.storage/?view=azps-15.0.0) and the required [Microsoft.Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-1.0) PowerShell modules, if not already installed.

## Authenticate

Before you begin, make sure you meet the prerequisites above. Then, open a PowerShell session. PowerShell 7 is preferred, but PowerShell 5 (aka Windows PowerShell) is also acceptable.

In order to use RestSetAcls on an Azure Storage account, you need to define how to authenticate to the account. You should do this using [New-AzStorageContext](https://learn.microsoft.com/en-us/powershell/module/az.storage/new-azstoragecontext). The sections below describe a few common ways to authenticate to Azure Files.

### Option 1: Account key authentication

The simplest way to authenticate is to use your storage account name and key. This will use [Shared Key authentication](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key).

> [!WARNING]
> Storage account keys provide full admin access to all resources in a storage account. For this reason, using the account key is not recommended for production scenarios. Consider using a SAS token or OAuth authentication instead.


```powershell
$AccountName = "<storage-account-name>" # replace with the storage account name
$AccountKey = "<storage-account-key>" # replace with the storage account key

$context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
```

### Option 2: Account SAS authentication

You can also use an [account Shared Access Signature (SAS) token](https://learn.microsoft.com/en-us/rest/api/storageservices/create-account-sas) to authenticate.

SAS tokens are derived from the account key, but they can be scoped to specific services, resource types, and permissions, and they can have a limited lifetime. This makes them more secure than using the account key directly. To create an account SAS token, you can use [New-AzStorageAccountSASToken](https://learn.microsoft.com/en-us/powershell/module/az.storage/new-azstorageaccountsastoken) cmdlet as follows:

```powershell
$AccountName = "<storage-account-name>" # replace with the storage account name
$AccountKey = "<storage-account-key>" # replace with the storage account key

$context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
$sasToken = New-AzStorageAccountSASToken -Context $context -Service File -ResourceType Container,Object  -Permission "rwl" -ExpiryTime (Get-Date).AddDays(1)
```

Then, you can create a new context using the SAS token:

```powershell
$context = New-AzStorageContext -StorageAccountName $AccountName -SasToken $sasToken
```

### Option 3: Service SAS authentication

Account SAS tokens provide access to all resources in a storage account. If you want to limit access to a specific file share, or even to a specific sub-path in a file share, you can use a [service Shared Access Signature (SAS) token](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas) instead.

To create a service SAS token, you can use the [New-AzStorageFileSASToken](https://learn.microsoft.com/en-us/powershell/module/az.storage/new-azstoragefilesastoken) cmdlet as follows:

```powershell
$AccountName = "<storage-account-name>" # replace with the storage account name
$AccountKey = "<storage-account-key>" # replace with the storage account key
$FileShareName = "<file-share-name>" # replace with the name of your file share

$context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
$sasToken = New-AzStorageFileSASToken -Context $context -ShareName $FileShareName -Path "/" -Permission "rwl" -Protocol HttpsOnly -ExpiryTime (Get-Date).AddDays(1)
```

### Option 4: OAuth authentication

Account SAS and service SAS tokens are derived from the account key. If you want to avoid using the account key altogether, you can use [OAuth authentication](https://learn.microsoft.com/en-us/azure/storage/files/authorize-oauth-rest). 

To use OAuth authentication, you will need to grant your principal the `Storage File Data Privileged Reader` (read-only) or `Storage File Data Privileged Contributor` (read-write) role on the storage account or file share. Then you should log in using [Connect-AzAccount](https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount) and create a context as follows:

```powershell
$AccountName = "<storage-account-name>" # replace with the storage account name

Connect-AzAccount # If you have multiple tenants or subscriptions, you may need to add -TenantId or -Subscription parameters
$context = New-AzStorageContext -StorageAccountName $AccountName -EnableFileBackupRequestIntent -UseConnectedAccount
```

## Usage

This section assumes you have already created a `$context` using one of the methods above. You can then use the functions in this module to get or set ACLs on files and folders in your Azure file share. An overview of the available functions is provided below.

| Function                       | Description                                                            | Documentation                                 |
|--------------------------------|------------------------------------------------------------------------|-----------------------------------------------|
| `Convert-SecurityDescriptor`   | Utility function to convert between different permissions formats      | [docs](./docs/Convert-SecurityDescriptor.md)   |
| `Write-SecurityDescriptor`     | Utility function to pretty-print a permission                          | [docs](./docs/Write-SecurityDescriptor.md)     |
| `Write-AccessMask`             | Utility function to pretty-print a permission access mask              | [docs](./docs/Write-AccessMask.md)             |
| `Set-AzFileAclRecursive`       | Set the same ACL recursively on all files and folders under a path     | [docs](./docs/Set-AzFileAclRecursive.md)       |
| `New-AzFileAcl`                | Create a new ACL (but do not apply it), and get its ACL key back       | [docs](./docs/New-AzFileAcl.md)                |
| `Set-AzFileAclKey`             | Set the ACL key of a file or folder                                    | [docs](./docs/Set-AzFileAclKey.md)             |
| `Get-AzFileAclKey`             | Get the ACL key of a file or folder                                    | [docs](./docs/Get-AzFileAclKey.md)             |
| `Get-AzFileAclFromKey`         | Get the ACL value of a key                                             | [docs](./docs/Get-AzFileAclFromKey.md)         |
| `Set-AzFileAcl`                | Set the ACL value of a file or folder                                  | [docs](./docs/Set-AzFileAcl.md)                |
| `Get-AzFileAcl`                | Get the ACL value of a file or folder                                  | [docs](./docs/Get-AzFileAcl.md)                |
| `Set-AzFileOwner`              | Update the owner field of the ACL of a file or a folder                | [docs](./docs/Set-AzFileOwner.md)              |
| `Restore-AzFileAclInheritance` | Apply inheritance rules (recursively) on file and folders under a path | [docs](./docs/Restore-AzFileAclInheritance.md) |
| `Add-AzFileAce`                | Add an Access Control Entry (ACE) to a file or folder                  | [docs](./docs/Add-AzFileAce.md)                |

The terminology used in this module is explained below:

- **Security Descriptor**: A structure that encodes the owner, group, and permissions of a file or folder.
- **Access Control List (ACL)**: The part of the security descriptor that encodes the permissions of a file or folder. Since the ACL is the most important part of the security descriptor, we often use "ACL" to refer to the entire security descriptor, including owner and group.
- **Access Control Entry (ACE)**: An entry in the ACL that encodes the permissions for a specific user or group.

## Uninstall

To uninstall, run:

```powershell
Uninstall-Module RestSetAcls
```

To uninstall dependencies that were installed along with RestSetAcls, see:

- [Uninstall Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/uninstall-az-ps?view=azps-15.1.0)
- [Uninstall Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0#uninstalling-the-sdk)