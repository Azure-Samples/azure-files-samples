function Ask([Parameter(Mandatory=$true)][string] $question)
{
    while ($true) {
        $yn = Read-Host "${question} [Y/n]"
        $yn = $yn.Trim().ToLower()
        if ($yn -eq 'n') {
            return $false
        } elseif ($yn -eq '' -or $yn -eq 'y') {
            return $true
        }
        Write-Host "Invalid answer '$yn'. Answer with either 'y' or 'n'" -ForegroundColor Red
    }
}

function Get-IsPowerShellIse {
    return $host.Name -eq "Windows PowerShell ISE Host"
}

function Get-SpecialCharactersPrintable {
    # Windows Terminal supports it
    if ($env:WT_SESSION) {
        return $true
    }

    # PowerShell 6+ supports it
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return $true
    }

    # Older versions don't
    return $false
}

function Write-LiveFilesAndFoldersProcessingStatus {
    [OutputType([int])]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object[]]$FileOrFolder,

        [Parameter(Mandatory=$true)]
        [datetime]$StartTime,

        [Parameter(Mandatory=$false)]
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
    }

    end {
        return $i
    }
}

function Write-FinalFilesAndFoldersProcessed {
    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory=$true)]
        [int]$ProcessedCount,

        [Parameter(Mandatory=$true)]
        [hashtable]$Errors,

        [Parameter(Mandatory=$true)]
        [timespan]$TotalTime,

        [Parameter(Mandatory=$false)]
        [int]$MaxErrorsToShow = 10
    )

     # Backwards compat with older PowerShell versions
    $specialChars = Get-SpecialCharactersPrintable
    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
    $doneStatus = if ($specialChars) { "($checkmark) Done: " } else { "Done: " }
    $partialStatus = if ($specialChars) { "($cross) Partial: " } else { "Partial: " }
    $failedStatus = if ($specialChars) { "($cross) Failed: " } else { "Failed: " }

    $successCount = $ProcessedCount - $Errors.Count
    $errorCount = $Errors.Count

    $seconds = [math]::Round($TotalTime.TotalSeconds, 2)

    if ($errorCount -gt 0) {        
        if ($errorCount -eq $processedCount) {
            # Setting ACLs failed for all files; report it.
            Write-Host $failedStatus -ForegroundColor Red -NoNewline
            Write-Host "Failed to set " -NoNewline
            Write-Host $errorCount -ForegroundColor Red -NoNewline
            Write-Host " permissions. Total time " -NoNewline
            Write-Host $seconds -ForegroundColor Blue -NoNewline
            Write-Host " seconds. Errors:"
        }
        else {
            Write-Host $partialStatus -ForegroundColor Yellow -NoNewline
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
    } else {
        $itemsPerSec = [math]::Round($successCount / $TotalTime.TotalSeconds, 1)

        Write-Host $doneStatus -ForegroundColor Green -NoNewline
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

function Get-AzureFilesRecursive {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase[]]$DirectoryContents,

        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,

        [Parameter(Mandatory=$false)]
        [string]$DirectoryPath = "",

        [Parameter(Mandatory=$false)]
        [switch]$SkipFiles = $false,

        [Parameter(Mandatory=$false)]
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
            $subdirectoryContents = Get-AzStorageFile -Directory $file.CloudFileDirectory

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
                File = $file   
            }
        }
    }
}

function New-AzFilePermission {
    [OutputType([string])]
    param (
        [Parameter(Mandatory=$true, HelpMessage="Azure storage context")]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,

        [Parameter(Mandatory=$true, HelpMessage="Name of the file share")]
        [string]$FileShareName,
        
        [Parameter(
            Mandatory=$true,
            HelpMessage="File permission in the Security Descriptor Definition Language (SDDL). " +
                        "SDDL must have an owner, group, and discretionary access control list (DACL). " +
                        "The provided SDDL string format of the security descriptor should not have " +
                        "domain relative identifier (like 'DU', 'DA', 'DD' etc) in it.")]
        [string]$Sddl
    )

    $share = Get-AzStorageShare -Name $FileShareName -Context $Context
    $permissionInfo = $share.ShareClient.CreatePermission($Sddl)
    return $permissionInfo.Value.FilePermissionKey
}

function Set-AzureFilesPermissionKey {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory=$true)]
        [string]$FilePermissionKey
    )

    $smbProperties = New-Object Azure.Storage.Files.Shares.Models.FileSmbProperties
    $smbProperties.FilePermissionKey = $FilePermissionKey

    if ($File.GetType().Name -eq "AzureStorageFileDirectory") {
        $directory = [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFileDirectory]$File
        $directory.ShareDirectoryClient.SetHttpHeaders($smbProperties) | Out-Null
    } else {
        $file = [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile]$File
        $file.ShareFileClient.SetHttpHeaders(
            $null, # newSize
            $null, # httpHeaders
            $smbProperties
        ) | Out-Null
    }
}

function Set-AzureFilesAcl {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase]$File,

        [Parameter(Mandatory=$true)]
        [string]$SddlPermission
    )
    
    if ($File.GetType().Name -eq "AzureStorageFileDirectory") {
        $directory = [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFileDirectory]$File
        $directory.ShareDirectoryClient.SetHttpHeaders(
            $null, # SmbProperties
            $SddlPermission # filePermission
        ) | Out-Null
    } else {
        $file = [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile]$File
        $file.ShareFileClient.SetHttpHeaders(
            $null, # newSize
            $null, # httpHeaders
            $null, # smbProperties
            $SddlPermission # filePermission
        )  | Out-Null
    }
}

function Set-AzureFilesAclRecursive {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,

        [Parameter(Mandatory=$true)]
        [string]$FileShareName,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$SddlPermission,

        [Parameter(Mandatory=$false)]
        [bool]$Parallel = $true,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 10,

        [Parameter(Mandatory=$false)]
        [switch]$SkipFiles = $false,

        [Parameter(Mandatory=$false)]
        [switch]$SkipDirectories = $false
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

    # Try to create permission
    # The idea is to create the permission early. If this fails (e.g. due to invalid SDDL), we can fail early.
    # Setting permission key should in theory also be slightly faster than setting SDDL directly (though this may not be noticeable in practice).
    try {
        $filePermissionKey = New-AzFilePermission -Context $Context -FileShareName $FileShareName -Sddl $SddlPermission
    } catch {
        Write-Host $failedStatus -ForegroundColor Red -NoNewline
        Write-Host "Failed to create file permission" -ForegroundColor Red
        Write-Host 
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }

    # Get root directory
    # Calling Get-AzStorageFile with this parameter set returns a AzureStorageFileDirectory
    # (if the path is a directory) or AzureStorageFile (if the path is a file).
    # If it's a directory, Get-AzureFilesRecursive will get its contents. 
    try {
        $directory = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath -ErrorAction Stop
    } catch {
        Write-Host $failedStatus -ForegroundColor Red -NoNewline
        Write-Host "Failed to read root directory"
        Write-Host
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }

    $startTime = Get-Date
    $processedCount = 0
    $errors = @{}
    $ProgressPreference = "SilentlyContinue"

    if ($Parallel) {
        $funcDef = ${function:Set-AzureFilesPermissionKey}.ToString()
        $processedCount = Get-AzureFilesRecursive `
            -Context $Context `
            -DirectoryContents @($directory) `
            -SkipFiles:$SkipFiles `
            -SkipDirectories:$SkipDirectories `
        | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Set the ACL
            ${function:Set-AzureFilesPermissionKey} = $using:funcDef
            $errorMessage = $null            
            try {
                Set-AzureFilesPermissionKey -File $_.File -FilePermissionKey $using:filePermissionKey
            } catch {
                $errorMessage = $_.Exception.Message
            }
            Write-Output @{
                FullPath = $_.FullPath
                ErrorMessage = $errorMessage
            }
        } `
        | ForEach-Object {
            $success = $true
            
            # Can't write in the parallel block, so we write here
            if ($null -ne $_.ErrorMessage) {
                $errors[$_.FullPath] = $_.ErrorMessage
                $success = $false
            }

            Write-Output @{
                FullPath = $_.FullPath
                Success = $success
            }
        } `
        | Write-LiveFilesAndFoldersProcessingStatus -RefreshRateHertz 10 -StartTime $startTime
    } else {
        $processedCount = Get-AzureFilesRecursive `
            -Context $Context `
            -DirectoryContents @($directory) `
            -SkipFiles:$SkipFiles `
            -SkipDirectories:$SkipDirectories `
        | ForEach-Object {
            # Set the ACL
            $fullPath = $_.FullPath
            $success = $true
            try {
                Set-AzureFilesPermissionKey -File $_.File -FilePermissionKey $filePermissionKey
            } catch {
                $errors[$fullPath] = $_.Exception.Message
                $success = $false
            }
            Write-Output @{
                FullPath = $_.FullPath
                Success = $success
            }
        } `
        | Write-LiveFilesAndFoldersProcessingStatus -RefreshRateHertz 10 -StartTime $startTime
    }

    $ProgressPreference = "Continue"
    
    $totalTime = (Get-Date) - $startTime
    Write-Host "`r" -NoNewline # Clear the line from the live progress reporting
    Write-FinalFilesAndFoldersProcessed -ProcessedCount $processedCount -Errors $errors -TotalTime $totalTime
}
