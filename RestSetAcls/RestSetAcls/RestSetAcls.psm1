. $PSScriptRoot/Convert.ps1
. $PSScriptRoot/SddlUtils.ps1
. $PSScriptRoot/PrintUtils.ps1
Import-Module $PSScriptRoot/Interop.psm1

function Write-LiveFilesAndFoldersProcessingStatus {
    [OutputType([int])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter",
        "FileOrFolder",
        Justification = "We don't print `$FileOrFolder but we do want to iterate over it")]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object[]]$FileOrFolder,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [int]$RefreshRateHertz = 10
    )

    begin {
        $i = 0
        $failures = 0
        $msBetweenPrints = 1000 / $RefreshRateHertz
        $lastPrint = (Get-Date).AddMilliseconds(-$msBetweenPrints)
        $overwriteLine = -not (Get-IsPowerShellIse)
    }

    process {
        $i++
        $timeSinceLastPrint = (Get-Date) - $lastPrint

        if (-not $_.Success) {
            $failures++
        }
        
        # To avoid overloading gui, only print at most every $msBetweenPrints
        # On a test with 6K files, printing at 60Hz saved ~20% perf compared to printing every update
        if ($timeSinceLastPrint.TotalMilliseconds -gt $msBetweenPrints) {
            $now = Get-Date
            $timeSinceStart = $now - $StartTime
            $itemsPerSec = [math]::Round($i / $timeSinceStart.TotalSeconds, 1)

            if ($overwriteLine) {
                Write-Host "`r" -NoNewline
            }
            Write-Host "Set " -ForegroundColor DarkGray -NoNewline
            Write-Host ($i - $failures) -ForegroundColor Blue -NoNewline
            Write-Host " permissions" -ForegroundColor DarkGray -NoNewline
            if ($failures -gt 0) {
                Write-Host ", " -ForegroundColor DarkGray -NoNewline
                Write-Host $failures -ForegroundColor Red -NoNewline
                Write-Host " failures" -ForegroundColor DarkGray -NoNewline
            }
            Write-Host " (" -ForegroundColor DarkGray -NoNewline
            Write-Host $itemsPerSec -ForegroundColor Blue -NoNewline
            Write-Host " items/s)" -ForegroundColor DarkGray -NoNewline
            if (-not $overwriteLine) {
                Write-Host
            }
            
            $lastPrint = Get-Date
        }

        Write-Output $_
    }
}

function Write-FinalFilesAndFoldersProcessed {
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$ProcessedCount,

        [Parameter(Mandatory = $true)]
        [hashtable]$Errors,

        [Parameter(Mandatory = $true)]
        [timespan]$TotalTime,

        [Parameter(Mandatory = $false)]
        [int]$MaxErrorsToShow = 10
    )

    $successCount = $ProcessedCount - $Errors.Count
    $errorCount = $Errors.Count

    $seconds = [math]::Round($TotalTime.TotalSeconds, 2)

    if ($errorCount -gt 0) {        
        if ($errorCount -eq $processedCount) {
            # Setting ACLs failed for all files; report it.
            Write-FailedHeader
            Write-Host "Failed to set " -NoNewline
            Write-Host $errorCount -ForegroundColor Red -NoNewline
            Write-Host " permissions. Total time " -NoNewline
            Write-Host $seconds -ForegroundColor Blue -NoNewline
            Write-Host " seconds. Errors:"
        }
        else {
            Write-PartialHeader
            Write-Host "Set " -NoNewline
            Write-Host $successCount -ForegroundColor Blue -NoNewline
            Write-Host " permissions, " -NoNewline
            Write-Host $errorCount -ForegroundColor Red -NoNewline
            Write-Host " failures. Total time " -NoNewline
            Write-Host $seconds -ForegroundColor Blue -NoNewline
            Write-Host " seconds. Errors:"
        }
        Write-Host
        
        # Print first $maxErrorsToShow errors
        $Errors.GetEnumerator() | Select-Object -First $MaxErrorsToShow | ForEach-Object {
            Write-Host "  $($_.Key): " -NoNewline
            Write-Host $_.Value -ForegroundColor Red
        }

        # Add a note if there are more errors
        if ($errorCount -gt $MaxErrorsToShow) {
            Write-Host "  ... and " -NoNewline
            Write-Host ($errorCount - $MaxErrorsToShow) -ForegroundColor Red -NoNewline
            Write-Host " more errors"
            Write-Host
        }
        
        # Save all errors to a JSON file
        ConvertTo-Json $Errors | Out-File "errors.json"
        Write-Host "  Full list of errors has been saved in " -NoNewline
        Write-Host "errors.json" -ForegroundColor Blue
        
        Write-Host
    }
    else {
        $itemsPerSec = [math]::Round($successCount / $TotalTime.TotalSeconds, 1)

        Write-DoneHeader
        Write-Host "Set " -NoNewline
        Write-Host $successCount -ForegroundColor Blue -NoNewline
        Write-Host " permissions in " -NoNewline
        Write-Host $seconds -ForegroundColor Blue -NoNewline
        Write-Host " seconds" -NoNewline
        Write-Host " (" -NoNewline
        Write-Host $itemsPerSec -ForegroundColor Blue -NoNewline
        Write-Host " items/s)"
    }
}

function Write-SddlWarning {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Sddl,

        [Parameter(Mandatory = $true)]
        [string]$NewSddl
    )
    Write-WarningHeader
    Write-Host "The SDDL string has non-standard inheritance rules."
    Write-Host "It is recommended to set OI (Object Inherit) and CI (Container Inherit) on every permission. " -ForegroundColor DarkGray
    Write-Host "This ensures that the permissions are inherited by files and folders created in the future." -ForegroundColor DarkGray
    Write-Host
    Write-Host "   Current:     "  -NoNewline -ForegroundColor Yellow
    Write-Host $Sddl
    Write-Host "   Recommended: " -NoNewline -ForegroundColor Green
    Write-Host $NewSddl
    Write-Host

    Write-Host "Do you want to continue with the " -NoNewline
    Write-Host "current" -ForegroundColor Yellow -NoNewline
    Write-Host " SDDL?" -NoNewline

    return Ask ""
}

function Get-ShareName {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File
    )

    if ($File.GetType().Name -eq "AzureStorageFileDirectory") {
        return $File.ShareDirectoryClient.ShareName
    }
    else {
        return $File.ShareFileClient.ShareName
    }
}

function Get-ClientFromFile {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File
    )

    if ($File -is [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFileDirectory]) {
        return $File.ShareDirectoryClient
    }
    elseif ($File -is [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile]) {
        return $File.ShareFileClient
    }
    else {
        throw "Invalid parameter File. Expected AzureStorageFileDirectory or AzureStorageFile."
    }
}

function Get-IsDirectoryClient {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [object]$Client
    )

    if ($Client -is [Azure.Storage.Files.Shares.ShareDirectoryClient]) {
        return $true
    }
    elseif ($Client -is [Azure.Storage.Files.Shares.ShareFileClient]) {
        return $false
    }
    else {
        throw "Invalid parameter Client. Expected ShareDirectoryClient or ShareFileClient."
    }
}

function Get-ShareClientFromFileOrDirectoryClient {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [object]$Client
    )

    if ($Client -is [Azure.Storage.Files.Shares.ShareDirectoryClient] -or
        $Client -is [Azure.Storage.Files.Shares.ShareFileClient]) {
        return [Azure.Storage.Files.Shares.Specialized.SpecializedShareExtensions]::GetParentShareClient($Client)
    }
    else {
        throw "Invalid parameter Client. Expected ShareDirectoryClient or ShareFileClient."
    }
}

function Get-AzureFilesRecursive {
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase[]]$DirectoryContents,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $false)]
        [string]$DirectoryPath = "",

        [Parameter(Mandatory = $false)]
        [switch]$SkipFiles = $false,

        [Parameter(Mandatory = $false)]
        [switch]$SkipDirectories = $false
    )

    foreach ($file in $DirectoryContents) {
        $fullPath = "${DirectoryPath}$($file.Name)"
        $isDirectory = $file.GetType().Name -eq "AzureStorageFileDirectory"

        $file.Context = $Context

        if ($isDirectory) {
            $fullPath += "/"

            # Get the contents of the directory.
            # Calling Get-AzStorageFile with this parameter set returns an Object[],
            # where items are either AzureStorageFile or AzureStorageFileDirectory.
            # Therefore, when recursing, we can cast Object[] to AzureStorageBase[].
            $subdirectoryContents = Get-AzStorageFile -Context $Context -ShareDirectoryClient $file.ShareDirectoryClient

            if ($null -ne $subdirectoryContents) {
                Get-AzureFilesRecursive `
                    -Context $Context `
                    -DirectoryContents $subdirectoryContents `
                    -DirectoryPath $fullPath `
                    -SkipFiles:$SkipFiles `
                    -SkipDirectories:$SkipDirectories
            }
        }

        if (($isDirectory -and !$SkipDirectories) -or (!$isDirectory -and !$SkipFiles)) {
            Write-Output @{
                FullPath = $fullPath
                File     = $file   
            }
        }
    }
}

function New-AzFileAcl {
<#
    .SYNOPSIS
    Creates a new Azure File ACL (Access Control List) for a specified file share.

    .DESCRIPTION
    The `New-AzFileAcl` function creates a new ACL for an Azure file share.
    It supports both SDDL (Security Descriptor Definition Language) and binary ACL formats.
    The function determines the ACL format if not explicitly provided and uploads the ACL to the specified file share.

    .PARAMETER Context
    Specifies the Azure storage context. This is required to authenticate and interact with the Azure storage account.

    .PARAMETER FileShareName
    Specifies the name of the Azure file share where the ACL will be applied.

    .PARAMETER ShareClient
    Specifies the Azure storage file share client with which the ACL will be applied.

    .PARAMETER Acl
    Specifies the ACL to be applied. This can be in SDDL format, base64-encoded binary, binary array, or RawSecurityDescriptor.

    .PARAMETER AclFormat
    Specifies the format of the ACL. If not provided, the function will infer the format automatically.

    .OUTPUTS
    System.String
    Returns the file permission key associated with the created ACL.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $acl = "O:BAG:SYD:(A;;FA;;;SY)"
    PS> New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl $acl -AclFormat Sddl

    Creates a new ACL in SDDL format for the specified file share and returns the file permission key.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $acl = "<base64-encoded ACL>"
    PS> New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl $acl  -AclFormat Base64

    Creates a new ACL for the specified file share, inferring the ACL format automatically, and returns the file permission key.

    .LINK
    Set-AzFileAclKey
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "FileShareName")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $true, ParameterSetName = "FileShareName")]
        [string]$FileShareName,

        [Parameter(Mandatory = $true, ParameterSetName = "FileShareClient")]
        [Azure.Storage.Files.Shares.ShareClient]$ShareClient,

        [Parameter(Mandatory = $true, ParameterSetName = "FileShareName")]
        [Parameter(Mandatory = $true, ParameterSetName = "FileShareClient")]
        [object]$Acl,

        [Parameter(Mandatory = $false, ParameterSetName = "FileShareName")]
        [Parameter(Mandatory = $false, ParameterSetName = "FileShareClient")]
        [SecurityDescriptorFormat]$AclFormat
    )

    begin {
        # Get a ShareClient instance from the parameters
        if ($PSCmdlet.ParameterSetName -eq "FileShareName") {
            $share = Get-AzStorageShare -Name $FileShareName -Context $Context
            $ShareClient = $share.ShareClient
        }

        # Infer AclFormat if not provided
        if (-not $AclFormat) {
            $AclFormat = Get-InferredAclFormat $Acl
            Write-Verbose "Inferred ACL format: $AclFormat. To override, use -AclFormat."
        }
    }

    process {
        # If it's SDDL, then upload the SDDL directly
        if ($AclFormat -eq "Sddl") {
            [string]$sddl = $Acl
            if ($PSCmdlet.ShouldProcess("File share '$($ShareClient.Name)'", "Create SDDL permission '$sddl'")) {
                $permissionInfo = $ShareClient.CreatePermission($sddl, [System.Threading.CancellationToken]::None)
                return $permissionInfo.Value.FilePermissionKey
            }
        }
        # All other formats should use the binary API
        else {
            $base64 = Convert-SecurityDescriptor $Acl -From $AclFormat -To Base64
            if ($PSCmdlet.ShouldProcess("File share '$($ShareClient.Name)'", "Create binary permission '$base64'")) {
                $permission = [Azure.Storage.Files.Shares.Models.ShareFilePermission]::new()
                $permission.Permission = $base64
                $permission.PermissionFormat = [Azure.Storage.Files.Shares.Models.FilePermissionFormat]::Binary
    
                $permissionInfo = $ShareClient.CreatePermission($permission, [System.Threading.CancellationToken]::None)
                return $permissionInfo.Value.FilePermissionKey
            }
        }
    }    
}

function Set-AzFileAclKey {
<#
    .SYNOPSIS
    Sets the Azure File ACL key on a specified file or directory.

    .DESCRIPTION
    The `Set-AzFileAclKey` takes an ACL key, and sets it on a specified file or directory in Azure Files.

    .PARAMETER File
    Specifies the Azure storage file or directory on which to set the ACL key.

    .PARAMETER Context
    Specifies the Azure storage context. This is required to authenticate and interact with the Azure storage account.

    .PARAMETER FileShareName
    Specifies the name of the Azure file share where the ACL will be applied.

    .PARAMETER Client
    Specifies the Azure storage file or directory client with which the ACL will be applied.

    .PARAMETER Key
    Specifies the ACL key to be applied. This is the key returned from the `New-AzFileAcl` function.

    .OUTPUTS
    System.String
    Returns the file permission key associated with the created ACL.
    Note that this may differ from the key that was passed in, as the permission applied to the file may be different,
    due to inheritance rules defined on the parent directory.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $key = New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl "O:BAG:SYD:(A;;FA;;;SY)" -AclFormat Sddl
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> Set-AzFileAclKey -File $file -Key $key

    Sets the specified ACL key on the given file.

    .LINK
    New-AzFileAcl
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "File")]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Azure storage context")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,
        
        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Name of the file share")]
        [string]$FileShareName,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Path to the file or directory on which to set the permission key")]
        [string]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = "Client")]
        [object]$Client,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Key
    )

    begin {
        # Ensure $Client and $isDirectory are initialized for all parameter sets
        if ($PSCmdlet.ParameterSetName -eq "FilePath") {
            $File = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath
            $Client = Get-ClientFromFile $File
        }
        elseif ($PSCmdlet.ParameterSetName -eq "File") {
            $Client = Get-ClientFromFile $File
        }

        $isDirectory = Get-IsDirectoryClient $Client
    }

    process {
        # Set the ACL

        $smbProperties = [Azure.Storage.Files.Shares.Models.FileSmbProperties]::new()
        $smbProperties.FilePermissionKey = $Key

        if ($isDirectory) {
            if ($PSCmdlet.ShouldProcess("Directory '$($Client.Path)'", "Set permission key '$Key'")) {
                $options = [Azure.Storage.Files.Shares.Models.ShareDirectorySetHttpHeadersOptions]::new()
                $options.SmbProperties = $smbProperties
                $response = $client.SetHttpHeaders($options)
                return $response.Value.SmbProperties.FilePermissionKey
            }
        }
        else {
            if ($PSCmdlet.ShouldProcess("File '$($Client.Path))'", "Set permission key '$Key'")) {
                $options = [Azure.Storage.Files.Shares.Models.ShareFileSetHttpHeadersOptions]::new()
                $options.SmbProperties = $smbProperties
                $response = $client.SetHttpHeaders($options)
                return $response.Value.SmbProperties.FilePermissionKey
            }
        }
    }
}

function Set-AzFileAcl {
<#
    .SYNOPSIS
    Sets the Access Control List (ACL) for a specified Azure file or directory.

    .DESCRIPTION
    The `Set-AzFileAcl` function applies an ACL to a specified Azure file or directory. 
    It supports both SDDL (Security Descriptor Definition Language) and binary ACL formats. 
    The function determines the ACL format if not explicitly provided and applies the ACL directly 
    or via a permission key, depending on the size of the ACL.

    .PARAMETER File
    Specifies the Azure storage file or directory on which to set the ACL.

    .PARAMETER Client
    Specifies the Azure storage file or directory client with which to set the ACL.

    .PARAMETER Acl
    Specifies the ACL to be applied. This can be in SDDL format, base64-encoded binary, binary array, or RawSecurityDescriptor.

    .PARAMETER AclFormat
    Specifies the format of the ACL. If not provided, the function will infer the format automatically. 
    Supported formats include SDDL, Base64, and Binary.

    .OUTPUTS
    System.String
    Returns the file permission key associated with the applied ACL.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> Set-AzFileAcl -File $file -Acl "O:BAG:SYD:(A;;FA;;;SY)" -AclFormat Sddl

    Sets the specified SDDL ACL on the given file.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> $binaryAcl = [byte[]](0x01, 0x02, 0x03, 0x04, ...)
    PS> Set-AzFileAcl -File $file -Acl $binaryAcl -AclFormat Binary

    Sets the specified binary ACL on the given file.

#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "File")]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory = $true, ParameterSetName = "Client")]
        [Object]$Client,
        
        [Parameter(Mandatory = $true, ParameterSetName = "File")]
        [Parameter(Mandatory = $true, ParameterSetName = "Client")]
        [object]$Acl,

        [Parameter(Mandatory = $false, ParameterSetName = "File")]
        [Parameter(Mandatory = $false, ParameterSetName = "Client")]
        [SecurityDescriptorFormat]$AclFormat
    )

    begin {
        # Convert parameters to a $Client, and determine if $isDirectory
        if ($PSCmdlet.ParameterSetName -eq "File") {
            $Client = Get-ClientFromFile $File
        }
        $isDirectory = Get-IsDirectoryClient $Client

        # Get the permission value to set from the parameters
        if (-not $AclFormat) {
            $AclFormat = Get-InferredAclFormat $Acl
            Write-Verbose "Inferred ACL format: $AclFormat. To override, use -AclFormat."
        }

        $permission = [Azure.Storage.Files.Shares.Models.ShareFilePermission]::new()
        if ($AclFormat -eq "Sddl") {
            $permission.Permission = $Acl
            $permission.PermissionFormat = [Azure.Storage.Files.Shares.Models.FilePermissionFormat]::Sddl
            $aclCreationFormat = [SecurityDescriptorFormat]::Sddl
        }
        else {
            $permission.Permission = Convert-SecurityDescriptor $Acl -From $AclFormat -To Base64
            $permission.PermissionFormat = [Azure.Storage.Files.Shares.Models.FilePermissionFormat]::Binary
            $aclCreationFormat = [SecurityDescriptorFormat]::Base64
        }
    }

    process {
        # If it's < 8 KiB, update directly via HTTP headers in a single request
        # If it's >= 8 KiB, create a new permission key and set it (two requests)
        if ($permission.Permission.Length -lt 8192) {
            if ($IsDirectory) {
                $options = [Azure.Storage.Files.Shares.Models.ShareDirectorySetHttpHeadersOptions]::new()
                $options.FilePermission = $permission

                if ($PSCmdlet.ShouldProcess("Directory '$($Client.Path)'", "Set permission '$($permission.Permission)' in format '$($permission.PermissionFormat)'")) {
                    $response = $Client.SetHttpHeaders($options)
                    return $response.Value.SmbProperties.FilePermissionKey
                }
            }
            else {
                $options = [Azure.Storage.Files.Shares.Models.ShareFileSetHttpHeadersOptions]::new()
                $options.FilePermission = $permission

                if ($PSCmdlet.ShouldProcess("File '$($Client.Path)'", "Set permission '$($permission.Permission)' in format '$($permission.PermissionFormat)'")) {
                    $response = $Client.SetHttpHeaders($options)
                    return $response.Value.SmbProperties.FilePermissionKey
                }
            }
        }
        else {
            $ShareClient = Get-ShareClientFromFileOrDirectoryClient $Client

            # Create a new permission key
            $key = New-AzFileAcl `
                -ShareClient $shareClient `
                -Acl $permission.Permission `
                -AclFormat $aclCreationFormat `
                -WhatIf:$WhatIfPreference
            
            if ([string]::IsNullOrEmpty($key)) {
                Write-Error "Failed to create file permission" -ErrorAction Stop
            }

            # Set the permission key
            return Set-AzFileAclKey -Client $Client -Key $key -WhatIf:$WhatIfPreference
        }
    }
}

function Get-AzFileAclKey {
<#
    .SYNOPSIS
    Retrieves the permission key from a file or directory in an Azure file share.

    .DESCRIPTION
    The `Get-AzFileAclKey` function retrieves the ACL key for a given file or directory in an Azure file share. 
    The ACL can be returned in various formats, including SDDL (Security Descriptor Definition Language) 
    or binary formats. The function supports retrieving the ACL from a file share specified either 
    directly or by its name and context.

    .PARAMETER File
    Specifies the Azure storage file or directory from which to retrieve the ACL key.

    .PARAMETER Context
    Specifies the Azure storage context. This is required to authenticate and interact with the Azure storage account.

    .PARAMETER FileShareName
    Specifies the name of the Azure file share from which to retrieve the ACL key.

    .PARAMETER FilePath
    Specifies the path to the file or directory from which to retrieve the ACL key.

    .PARAMETER Client
    Specifies the Azure storage file or directory client with which to retrieve the ACL key.

    .OUTPUTS
    System.String
    Returns the file permission key associated with the specified file or directory.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> Get-AzFileAclKey -File $file
    
    Retrieves the permission key for the specified file.
#>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Azure storage file or directory")]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Azure storage context")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,
        
        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Name of the file share")]
        [string]$FileShareName,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Path to the file or directory on which to set the permission key")]
        [string]$FilePath,

        [Parameter(Mandatory = $false, ParameterSetName = "Client")]
        [object]$Client
    )

    begin {
        # Get a $Client from the parameters
        if ($PSCmdlet.ParameterSetName -eq "FilePath") {
            $File = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath
            $Client = Get-ClientFromFile $File
        }
        elseif ($PSCmdlet.ParameterSetName -eq "File") {
            $Client = Get-ClientFromFile $File
        }
    }

    process {
        return $Client.GetProperties([System.Threading.CancellationToken]::None).Value.SmbProperties.FilePermissionKey
    }
}

function Get-AzFileAclFromKey {
<#
    .SYNOPSIS
    Retrieves the ACL (Access Control List) for a specified ACL key.

    .DESCRIPTION
    The `Get-AzFileAclFromKey` function retrieves the ACL for a specified ACL key. It supports retrieving the ACL in
    various formats, including SDDL (Security Descriptor Definition Language) or binary formats. The function supports
    retrieving the ACL from a file share specified either directly or its name and context.

    .PARAMETER Key
    Specifies the ACL key to be retrieved. This is the key returned from the `New-AzFileAcl`, `Set-AzFileAclKey`,
    or `Get-AzFileAclKey` functions.

    .PARAMETER Share
    Specifies the Azure storage file share from which to retrieve the ACL key.

    .PARAMETER Context
    Specifies the Azure storage context. This is required to authenticate and interact with the Azure storage account.

    .PARAMETER FileShareName
    Specifies the name of the Azure file share from which to retrieve the ACL key.

    .PARAMETER ShareClient
    Specifies the Azure storage file share client from which to retrieve the ACL key.

    .PARAMETER OutputFormat
    Specifies the output format of the security descriptor. Supported formats include SDDL, Base64, and Binary.

    .OUTPUTS
    System.String
    Returns the ACL in the specified format. The default format is SDDL.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> $key = Get-AzFileAclKey -File $file
    PS> Get-AzFileAclFromKey -Key $key -Share $file.Share -OutputFormat Sddl

    Retrieves the SDDL ACL for the specified file using the permission key.

    .LINK
    New-AzFileAcl

    .LINK
    Set-AzFileAcl

    .LINK
    Set-AzFileAclKey
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor], [string], [byte[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "Share")]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFileShare]$Share,

        [Parameter(Mandatory = $true, ParameterSetName = "FileShareName", HelpMessage = "Azure storage context")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $true, ParameterSetName = "FileShareName", HelpMessage = "Name of the file share")]
        [string]$FileShareName,

        [Parameter(Mandatory = $false, ParameterSetName = "ShareClient", HelpMessage = "Azure storage file share client")]
        [Azure.Storage.Files.Shares.ShareClient]$ShareClient,

        [Parameter(Mandatory = $false, HelpMessage = "Output format of the security descriptor")]
        [SecurityDescriptorFormat]$OutputFormat = [SecurityDescriptorFormat]::Sddl
    )
    begin {
        # Get a $ShareClient from the parameters
        if ($PSCmdlet.ParameterSetName -eq "FileShareName") {
            $ShareClient = (Get-AzStorageShare -Name $FileShareName -Context $Context).ShareClient
        }
        elseif ($PSCmdlet.ParameterSetName -eq "Share") {
            $ShareClient = $Share.ShareClient
        }
    }

    process {
        if ($PSCmdlet.ShouldProcess("File share '$($ShareClient.Name)'", "Get permission key '$Key'")) {
            if ($OutputFormat -eq [SecurityDescriptorFormat]::Sddl) {
                $format = [Azure.Storage.Files.Shares.Models.FilePermissionFormat]::Sddl
                $permissionInfo = $ShareClient.GetPermission($Key, $format, [System.Threading.CancellationToken]::None)
                $sddl = $permissionInfo.Value.Permission 
                return $sddl
            }
            else {
                $format = [Azure.Storage.Files.Shares.Models.FilePermissionFormat]::Binary
                $permissionInfo = $ShareClient.GetPermission($Key, $format, [System.Threading.CancellationToken]::None)
                $base64 = $permissionInfo.Value.Permission
                return Convert-SecurityDescriptor $base64 -From Base64 -To $OutputFormat  
            }
        }
    }
}

function Get-AzFileAcl {
<#
    .SYNOPSIS
    Retrieves the ACL (Access Control List) for a specified file or directory.

    .DESCRIPTION
    The `Get-AzFileAcl` function retrieves the ACL for a specified file or directory. It supports retrieving the ACL in
    various formats, including SDDL (Security Descriptor Definition Language) or binary formats. The function supports
    retrieving the ACL from a file share specified either directly or its name and context.

    .PARAMETER File
    Specifies the Azure storage file or directory from which to retrieve the ACL key.

    .PARAMETER Context
    Specifies the Azure storage context. This is required to authenticate and interact with the Azure storage account.

    .PARAMETER FileShareName
    Specifies the name of the Azure file share from which to retrieve the ACL key.

    .PARAMETER FilePath
    Specifies the path to the file or directory from which to retrieve the ACL key.

    .PARAMETER Client
    Specifies the Azure storage file share client with which to retrieve the ACL key.

    .PARAMETER OutputFormat
    Specifies the output format of the security descriptor. Supported formats include SDDL, Base64, and Binary.

    .OUTPUTS
    System.String
    Returns the ACL in the specified format. The default format is SDDL.

    .EXAMPLE
    PS> $context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
    PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
    PS> Get-AzFileAcl -File $file

    Retrieves the SDDL ACL for the specified file using the permission key.

    .LINK
    New-AzFileAcl

    .LINK
    Set-AzFileAcl

    .LINK
    Set-AzFileAclKey
#>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "File", HelpMessage = "Azure storage file or directory")]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Azure storage context")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,
        
        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Name of the file share")]
        [string]$FileShareName,

        [Parameter(Mandatory = $true, ParameterSetName = "FilePath", HelpMessage = "Path to the file or directory on which to set the permission key")]
        [string]$FilePath,

        [Parameter(Mandatory = $false, ParameterSetName = "Client")]
        [object]$Client,

        [Parameter(Mandatory = $false, HelpMessage = "Output format of the security descriptor")]
        [SecurityDescriptorFormat]$OutputFormat = [SecurityDescriptorFormat]::Sddl
    )

    begin {
        # Get a $Client from the parameters
        if ($PSCmdlet.ParameterSetName -eq "FilePath") {
            $File = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath
            $Client = Get-ClientFromFile $File
        }
        elseif ($PSCmdlet.ParameterSetName -eq "File") {
            $Client = Get-ClientFromFile $File
        }
    }

    process {
        $key = Get-AzFileAclKey -Client $Client
        
        if ([string]::IsNullOrEmpty($key)) {
            Write-Error "Failed to get file permission key" -ErrorAction Stop
        }

        $shareClient = Get-ShareClientFromFileOrDirectoryClient $Client
        return Get-AzFileAclFromKey -Key $key -ShareClient $shareClient -OutputFormat $OutputFormat

    }
}

function Set-AzFileAclRecursive {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands',
        'ForEach-Object/Parallel',
        Justification = "We are guarding the usage of -Parallel with a PowerShell version check")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands',
        'ForEach-Object/ThrottleLimit',
        Justification = "We are guarding the usage of -ThrottleLimit with a PowerShell version check")]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $true)]
        [string]$FileShareName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$SddlPermission,

        [Parameter(Mandatory = $false)]
        [bool]$Parallel = $true,

        [Parameter(Mandatory = $false)]
        [int]$ThrottleLimit = 10,

        [Parameter(Mandatory = $false)]
        [switch]$SkipFiles = $false,

        [Parameter(Mandatory = $false)]
        [switch]$SkipDirectories = $false,

        [Parameter(Mandatory = $false)]
        [switch]$WriteToPipeline = $false
    )

    if ($SkipFiles -and $SkipDirectories) {
        Write-Warning "Both -SkipFiles and -SkipDirectories are set. Nothing to do."
        return
    }

    # Check if parallel mode is supported
    if ($Parallel -and $PSVersionTable.PSVersion.Major -lt 7) {
        Write-Warning "-Parallel is only supported on PowerShell 7+. Falling back to single-threaded mode."
        $Parallel = $false
    }

    # Try to parse SDDL permission, check for common issues
    try {
        $securityDescriptor = ConvertTo-SecurityDescriptor $SddlPermission -InputFormat Sddl
    }
    catch {
        Write-Failure "SDDL permission is invalid"
        return
    }

    # Check if inheritance flags are okay
    $shouldBeEnabled = "ContainerInherit, ObjectInherit"
    $shouldBeDisabled = "NoPropagateInherit, InheritOnly"

    $matchesTarget = Get-AllAceFlagsMatch `
        -SecurityDescriptor $securityDescriptor `
        -EnabledFlags $shouldBeEnabled `
        -DisabledFlags $shouldBeDisabled

    if (-not ($matchesTarget)) {
        Set-AceFlags `
            -SecurityDescriptor $securityDescriptor `
            -EnableFlags $shouldBeEnabled `
            -DisableFlags $shouldBeDisabled

        $newSddl = ConvertFrom-SecurityDescriptor $securityDescriptor -OutputFormat Sddl

        $continue = Write-SddlWarning -Sddl $SddlPermission -NewSddl $newSddl
        if (-not $continue) {
            return
        }
    }

    # Try to create permission on Azure Files
    # The idea is to create the permission early. If this fails (e.g. due to invalid SDDL), we can fail early.
    # Setting permission key should in theory also be slightly faster than setting SDDL directly (though this may not be noticeable in practice).
    try {
        $filePermissionKey = New-AzFileAcl -Context $Context -FileShareName $FileShareName -Sddl $SddlPermission -WhatIf:$WhatIfPreference
        if ([string]::IsNullOrEmpty($filePermissionKey)) {
            Write-Failure "Failed to create file permission"
            return
        }
    }
    catch {
        Write-Failure "Failed to create file permission" -Details $_.Exception.Message
        return
    }

    # Get root directory
    # Calling Get-AzStorageFile with this parameter set returns a AzureStorageFileDirectory
    # (if the path is a directory) or AzureStorageFile (if the path is a file).
    # If it's a directory, Get-AzureFilesRecursive will get its contents. 
    try {
        $directory = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath -ErrorAction Stop
    }
    catch {
        Write-Failure "Failed to read root directory" -Details $_.Exception.Message
        return
    }

    $startTime = Get-Date
    $processedCount = 0
    $errors = @{}
    $ProgressPreference = "SilentlyContinue"

    if ($Parallel) {
        $funcDef = ${function:Set-AzFileAclKey}.ToString()
        Get-AzureFilesRecursive `
            -Context $Context `
            -DirectoryContents @($directory) `
            -SkipFiles:$SkipFiles `
            -SkipDirectories:$SkipDirectories `
        | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Set the ACL
            ${function:Set-AzFileAclKey} = $using:funcDef
            $success = $true
            $errorMessage = ""            
            try {
                Set-AzFileAclKey -File $_.File -Key $using:filePermissionKey -WhatIf:$using:WhatIfPreference
            }
            catch {
                $success = $false
                $errorMessage = $_.Exception.Message
            }
            
            # Write full output if requested, otherwise write minimal output
            if ($using:WriteToPipeline) {
                Write-Output @{
                    Time         = (Get-Date).ToString("o")
                    FullPath     = $_.FullPath
                    Permission   = $using:SddlPermission
                    Success      = $success
                    ErrorMessage = $errorMessage
                }
            }
            else {
                Write-Output @{
                    FullPath     = $_.FullPath
                    Success      = $success
                    ErrorMessage = $errorMessage
                }
            }
        } `
        | ForEach-Object {
            # Can't write in the parallel block, so we write here
            if (-not $_.Success) {
                $errors[$_.FullPath] = $_.ErrorMessage
            }
            $processedCount++
            Write-Output $_
        } `
        | Write-LiveFilesAndFoldersProcessingStatus -RefreshRateHertz 10 -StartTime $startTime `
        | ForEach-Object { if ($WriteToPipeline) { Write-Output $_ } }
    }
    else {       
        Get-AzureFilesRecursive `
            -Context $Context `
            -DirectoryContents @($directory) `
            -SkipFiles:$SkipFiles `
            -SkipDirectories:$SkipDirectories `
        | ForEach-Object {
            $fullPath = $_.FullPath
            $success = $true
            $errorMessage = ""
            
            # Set the ACL
            try {
                Set-AzFileAclKey -File $_.File -Key $filePermissionKey -WhatIf:$WhatIfPreference
            }
            catch {
                $success = $false
                $errorMessage = $_.Exception.Message
                $errors[$fullPath] = $errorMessage
            }

            $processedCount++
            
            # Write full output if requested, otherwise write minimal output
            if ($WriteToPipeline) {
                Write-Output @{
                    Time         = (Get-Date).ToString("o")
                    FullPath     = $fullPath
                    Permission   = $SddlPermission
                    Success      = $success
                    ErrorMessage = $errorMessage
                }
            }
            else {
                Write-Output @{
                    FullPath     = $fullPath
                    Success      = $success
                    ErrorMessage = $errorMessage
                }
            }            
        } `
        | Write-LiveFilesAndFoldersProcessingStatus -RefreshRateHertz 10 -StartTime $startTime `
        | ForEach-Object { if ($WriteToPipeline) { Write-Output $_ } }
    }

    $ProgressPreference = "Continue"
    
    $totalTime = (Get-Date) - $startTime
    Write-Host "`r" -NoNewline # Clear the line from the live progress reporting
    Write-FinalFilesAndFoldersProcessed -ProcessedCount $processedCount -Errors $errors -TotalTime $totalTime
}

function Restore-AzFileAclInheritance {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [Parameter(Mandatory = $true, ParameterSetName = "Recursive")]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [Parameter(Mandatory = $true, ParameterSetName = "Recursive")]
        [string]$FileShareName,

        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [string]$ParentPath,

        [Parameter(Mandatory = $true, ParameterSetName = "Single")]
        [string]$ChildPath,

        [Parameter(Mandatory = $true, ParameterSetName = "Recursive")]
        [switch]$Recursive,

        [Parameter(Mandatory = $true, ParameterSetName = "Recursive")]
        [string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq "Recursive") {
        $ParentPath = $Path
    }

    # Check that parent path exists and is a directory
    $parentFile = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $ParentPath
    if ($null -eq $parentFile) {
        Write-Host "The specified parent path '$ParentPath' does not exist." -ForegroundColor Red
        return
    }

    if ($parentFile -is [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile]) {
        Write-Host "The specified parent path '$ParentPath' is a file. Expected it to be a directory." -ForegroundColor Red
        return
    }

    # Dispatch to either recursive or single file processing
    if ($PSCmdlet.ParameterSetName -eq "Single") {
        $parentAcl = Get-AzFileAcl -File $parentFile -OutputFormat Raw

        return Restore-AzFileAclInheritanceSingle `
            -Context $Context `
            -FileShareName $FileShareName `
            -ParentAcl $parentAcl `
            -ChildPath $ChildPath `
            -WhatIf:$WhatIfPreference
    }
    elseif ($PSCmdlet.ParameterSetName -eq "Recursive" -and $Recursive) {  
        $startTime = Get-Date
        $processedCount = 0
        $errors = @{}

        Restore-AzFileAclInheritanceRecursive `
            -DirectoryClient $parentFile.ShareDirectoryClient `
            -PassThru `
            -WhatIf:$WhatIfPreference `
        | ForEach-Object {
            if (-not $_.Success) {
                $errors[$_.Path] = "failed"
            }
            $processedCount++
            Write-Output $_
        }
        | Write-LiveFilesAndFoldersProcessingStatus -RefreshRateHertz 10 -StartTime $startTime `
        | ForEach-Object { if ($PassThru) { Write-Output $_ } }

        Write-Host "`r" -NoNewline # Clear the line from the live progress reporting
        Write-FinalFilesAndFoldersProcessed `
            -ProcessedCount $processedCount `
            -Errors $errors `
            -TotalTime ((Get-Date) - $startTime)
    }
}

function Restore-AzFileAclInheritanceSingle {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Security.AccessControl.GenericSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.IStorageContext]$Context,

        [Parameter(Mandatory = $true)]
        [string]$FileShareName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Security.AccessControl.GenericSecurityDescriptor]$ParentAcl,

        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )

    # Presupposition: the parent path exists and is a directory. It is the responsibility of the caller to check this.

    # Check that the child path exists
    $childFile = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $ChildPath
    if ($null -eq $childFile) {
        Write-Host "The specified child path '$ChildPath' does not exist." -ForegroundColor Red
        return
    }

    # Get parent and child ACLs
    $childAcl = Get-AzFileAcl -File $childFile -OutputFormat Raw
    $childIsFolder = $childFile -is [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFileDirectory]

    # Compute inheritance
    $newChildAcl = CreatePrivateObjectSecurityEx `
        -ParentDescriptor $ParentAcl `
        -CreatorDescriptor $childAcl `
        -IsDirectory $childIsFolder

    $parentSddl = ConvertFrom-SecurityDescriptor $parentAcl -To Sddl
    $childSddl = ConvertFrom-SecurityDescriptor $newChildAcl -To Sddl
    $childNewSddl = ConvertFrom-SecurityDescriptor $childAcl -To Sddl
    Write-Verbose "Parent SDDL: $parentSddl"
    Write-Verbose "Child SDDL: $childSddl"
    Write-Verbose "New child SDDL: $childNewSddl"

    # Update ACL according to inheritance
    if ($PSCmdlet.ShouldProcess("File share '$($FileShareName)'", "Apply inheritance from '$ParentPath' to '$ChildPath'")) {
        Set-AzFileAcl -File $childFile -Acl $newChildAcl -AclFormat Sddl -WhatIf:$WhatIfPreference
    }

    return $newChildAcl
}

function Restore-AzFileAclInheritanceRecursive {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Security.AccessControl.GenericSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true)]
        [Azure.Storage.Files.Shares.ShareDirectoryClient]$DirectoryClient,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru = $false
    )

    # Presupposition: the parent path exists and is a directory. It is the responsibility of the caller to check this.
    $directoryPermissionKey = $DirectoryClient.GetProperties().Value.SmbProperties.FilePermissionKey

    $shareClient = Get-ShareClientFromFileOrDirectoryClient $DirectoryClient

    $options = [Azure.Storage.Files.Shares.Models.ShareDirectoryGetFilesAndDirectoriesOptions]::new()
    $options.IncludeExtendedInfo = $true
    $options.Traits = [Azure.Storage.Files.Shares.Models.ShareFileTraits]::PermissionKey

    # Recursively visit all subdirectories. This is a breadth-first search.
    $stack = [System.Collections.Generic.Stack[PSCustomObject]]::new()
    $stack.Push([PSCustomObject]@{
        DirectoryClient = $DirectoryClient
        DirectoryPermissionKey = $directoryPermissionKey
    })

    while ($stack.Count -gt 0) {
        $popped = $stack.Pop()
        $directoryClient = $popped.DirectoryClient
        $directoryPermissionKey = $popped.DirectoryPermissionKey

        # Get permission of parent directory
        $directoryPermission = $null
        if ($null -eq $directoryPermissionKey) {
            Write-Verbose "The directory '$($directoryClient.Name)' does not have a permission key..."
        }
        else {
            $directoryPermission = Get-AzFileAclFromKey `
                -Key $directoryPermissionKey `
                -ShareClient $shareClient `
                -OutputFormat FolderAcl
        }

        # Iterate over the contents of the directory
        foreach ($item in $directoryClient.GetFilesAndDirectories($options).GetEnumerator()) {
            $itemPermissionFormat = if ($item.IsDirectory) { "FolderAcl" } else { "FileAcl" }

            # Get ACL for the item
            $itemPermission = Get-AzFileAclFromKey `
                -Key $item.PermissionKey `
                -ShareClient $shareClient `
                -OutputFormat $itemPermissionFormat

            # Compute inheritance
            $itemNewPermission = CreatePrivateObjectSecurityEx `
                -ParentDescriptor $directoryPermission `
                -CreatorDescriptor $itemPermission `
                -IsDirectory $item.IsDirectory
            
            # Set new ACL on the item
            $itemClient = if ($item.IsDirectory) {
                $directoryClient.GetSubdirectoryClient($item.Name)
            } else {
                $directoryClient.GetFileClient($item.Name)
            }

            $parentSddl = Convert-SecurityDescriptor $directoryPermission -From FolderAcl -To Sddl
            $creatorSddl = Convert-SecurityDescriptor $itemPermission -From $itemPermissionFormat -To Sddl
            $newSddl = Convert-SecurityDescriptor $itemNewPermission -From $itemPermissionFormat -To Sddl

            Write-Verbose "Computed inheritance for item '$($itemClient.Path)'"
            Write-Verbose "Parent SDDL: $parentSddl"
            Write-Verbose "Creator SDDL: $creatorSddl"
            Write-Verbose "New SDDL: $newSddl"

            $newPermissionKey = Set-AzFileAcl `
                -Client $itemClient `
                -Acl $itemNewPermission `
                -AclFormat $itemPermissionFormat `
                -WhatIf:$WhatIfPreference
            
            # Write to the pipeline
            if ($PassThru) {
                Write-Output @{
                    Path = $itemClient.Path
                    IsDirectory = $item.IsDirectory
                    NewPermission = (Convert-SecurityDescriptor $itemNewPermission -To Sddl)
                    PermissionKey = $newPermissionKey
                    Success = $true
                }
            }

            # If item is a directory, push it onto the stack
            if ($item.IsDirectory) {
                $stack.Push([PSCustomObject]@{
                    DirectoryClient = $itemClient
                    DirectoryPermissionKey = $newPermissionKey
                })
            }
        }
    }   
}