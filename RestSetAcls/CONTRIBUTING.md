# Contributing

> [!WARNING]
> These instructions are only meant for contributors to this project.
> If you want to use the script, refer to the README.

## Setting up a test

1. Create a new Azure Storage account with a file share. Take note of the storage account key.
1. Define the following in your PowerShell session:

    ```powershell
    $AccountName = "<storage-account-name>" # replace with the storage account name
    $AccountKey = "<storage-account-key>" # replace with the storage account key
    $FileShareName = "<file-share-name>" # replace with the name of your file share

    $context = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
    ```

1. Mount the file share to a local drive

    ```powershell
    net use X: \\${AccountName}.file.core.windows.net\${FileShareName} /u:${AccountName} $AccountKey
    ```

1. Create test files

    ```powershell
    .\RestSetAcls\TestSetup.ps1 -Context $context -FileShareName $FileShareName -NumberDirs 3 -NumberFilesPerDir 3 -Depth 1
    ```

    This will create a directory structure with 3 directories, each containing 3 files:

    ```plaintext
    Creating dir /dir-1
    Creating file /dir-1/file-1.txt
    Creating file /dir-1/file-2.txt
    Creating file /dir-1/file-3.txt
    Creating dir /dir-2
    Creating file /dir-2/file-1.txt
    Creating file /dir-2/file-2.txt
    Creating file /dir-2/file-3.txt
    Creating dir /dir-3
    Creating file /dir-3/file-1.txt
    Creating file /dir-3/file-2.txt
    Creating file /dir-3/file-3.txt
    ```

## Comparing the speed to icacls

1. Try to set permissions via icacls

    ```cmd
    icacls X:\ /t /grant "Everyone:(OI)(CI)F"
    ```

1. Compare the speed of this operation to the `Set-AzureFilesAclRecursive` function

    ```powershell
    Set-AzureFilesAclRecursive -Context $context -FileShareName $FileShareName -FilePath "/" -SddlPermission $sddl
    ```
