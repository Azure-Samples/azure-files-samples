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

function Get-AzureFilesRecursive {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageBase[]]$DirectoryContents,

        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,

        [Parameter(Mandatory=$false)]
        [string]$DirectoryPath = ""
    )

    foreach ($file in $DirectoryContents) {
        $fullPath = "${DirectoryPath}$($file.Name)"

        $file.Context = $Context

        if ($file.GetType().Name -eq "AzureStorageFileDirectory") {
            $fullPath += "/"

            # Get the contents of the directory.
            # Calling Get-AzStorageFile with this parameter set returns an Object[],
            # where items are either AzureStorageFile or AzureStorageFileDirectory.
            # Therefore, when recursing, we can cast Object[] to AzureStorageBase[].
            $subdirectoryContents = Get-AzStorageFile -Directory $file.CloudFileDirectory
            if ($null -ne $subdirectoryContents) {
                Get-AzureFilesRecursive -Context $Context -DirectoryContents $subdirectoryContents -DirectoryPath $fullPath
            }
        }

        Write-Output @{
            FullPath = $fullPath
            File = $file   
        }
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
        [switch]$SkipConfirm = $false,

        [Parameter(Mandatory=$false)]
        [switch]$Parallel = $false,

        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = 10
    )

    # Backwards compat with older PowerShell versions
    $specialChars = Get-SpecialCharactersPrintable
    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
    $doneStatus = if ($specialChars) { "($checkmark) Done: " } else { "Done: " }
    $partialStatus = if ($specialChars) { "($cross) Partial: " } else { "Partial: " }
    $failedStatus = if ($specialChars) { "($cross) Failed: " } else { "Failed: " }

    Write-Host "Step 1: Finding all files" -ForegroundColor White
    $startTime = Get-Date

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
    
    # Recursively find all files under the root directory
    $ProgressPreference = "SilentlyContinue"
    $i = 0
    $allFiles = Get-AzureFilesRecursive -Context $Context -DirectoryContents @($directory) | ForEach-Object {
        $i++
        Write-Debug $_
        Write-Host "`rFound " -ForegroundColor DarkGray -NoNewline
        Write-Host $i -ForegroundColor Blue -NoNewline
        Write-Host " files and folders" -ForegroundColor DarkGray -NoNewline
        $_
    }

    # Print success
    $totalTime = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
    Write-Host "`r$doneStatus" -ForegroundColor Green -NoNewline
    Write-Host "Found " -NoNewline
    Write-Host $allFiles.Count -ForegroundColor Blue -NoNewline
    Write-Host " files and folders in " -NoNewline
    Write-Host $totalTime -ForegroundColor Blue -NoNewline
    Write-Host " seconds"
    $ProgressPreference = "Continue"
    
    if (-not $SkipConfirm) {
        Write-Host
        $continue = Ask "Do you want update $($allFiles.Count) file permissions?"
        if (-not $continue) {
            return
        }
    }
    
    Write-Host

    Write-Host "Step 2: Setting ACLs" -ForegroundColor White
    $startTime = Get-Date
    $errors = @{}

    if ($Parallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "Using parallel mode" -ForegroundColor Yellow

        $funcDef = ${function:Set-AzureFilesAcl}.ToString()
        $allFiles | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            # Set the ACL
            ${function:Set-AzureFilesAcl} = $using:funcDef
            $errorMessage = $null            
            try {
                Set-AzureFilesAcl -File $_.File -SddlPermission $using:SddlPermission
            } catch {
                $errorMessage = $_.Exception.Message
            }
            return @{
                FullPath = $_.FullPath
                ErrorMessage = $errorMessage
            }
        } | ForEach-Object -Begin { $received = 0 } -Process {
            $received++
            
            $fileFullPath = $_.FullPath
            if ($null -ne $_.ErrorMessage) {
                $errors[$fileFullPath] = $_.ErrorMessage
            }

            # Calculate completion percentage
            $percentComplete = ($received / $allFiles.Count) * 100
            $roundedPercentComplete = [math]::Round($percentComplete, 2)
    
            # Calculate time remaining
            $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
            $averageSecondsPerFile = $elapsedSeconds / $received
            $remainingItems = $allFiles.Count - $received
            $secondsRemaining = $remainingItems * $averageSecondsPerFile
    
            # Print progress bar
            Write-Progress -Activity "Setting ACLs" -Status "${roundedPercentComplete}% - set ACL for $fileFullPath" `
                -PercentComplete $percentComplete `
                -SecondsRemaining $secondsRemaining
        }
    } else {
        if ($Parallel) {
            Write-Warning "-Parallel is only supported on PowerShell 7+. Falling back to single-threaded mode."
        } else {
            Write-Host "Using single-threaded mode" -ForegroundColor Yellow
        }

        # Single-threaded
        for ($i = 0; $i -lt $allFiles.Count; $i++) {
            $file = $allFiles[$i]
            $fileFullPath = $file.FullPath
    
            # Calculate completion percentage
            $percentComplete = ($i / $allFiles.Count) * 100
            $roundedPercentComplete = [math]::Round($percentComplete, 2)
    
            # Calculate time remaining
            $elapsedSeconds = ((Get-Date) - $startTime).TotalSeconds
            $averageSecondsPerFile = $elapsedSeconds / ($i + 1)
            $remainingItems = $allFiles.Count - $i - 1
            $secondsRemaining = $remainingItems * $averageSecondsPerFile
    
            # Print progress bar
            Write-Progress -Activity "Setting ACLs" -Status "${roundedPercentComplete}% - setting ACL for $fileFullPath" `
                -PercentComplete $percentComplete `
                -SecondsRemaining $secondsRemaining
    
            # Set the ACL
            try {
                Set-AzureFilesAcl -File $file.File -SddlPermission $SddlPermission
            } catch {
                $errors[$fileFullPath] = $_.Exception.Message
            }
        }
    }
    
    # Close the progress bar
    Write-Progress -Activity "Setting ACLs" -Status "Done" -Completed

    $totalTime = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
    if ($errors.Count -gt 0) {
        # Setting ACLs failed for some, but not all files. In such cases, it may be important
        # to know which files failed. We print the first 10, and put the rest in a JSON file.
        $maxErrorsToShow = 10
        
        if ($errors.Count -eq $allFiles.Count) {
            # Setting ACLs failed for all files; report it.
            Write-Host $failedStatus -ForegroundColor Red -NoNewline
            Write-Host "Failed to set " -NoNewline
            Write-Host $errors.Count -ForegroundColor Red -NoNewline
            Write-Host " ACLs. Total time " -NoNewline
            Write-Host $totalTime -ForegroundColor Blue -NoNewline
            Write-Host " seconds. Errors:"
        }
        else {
            Write-Host $partialStatus -ForegroundColor Yellow -NoNewline
            Write-Host "Set " -NoNewline
            Write-Host $($allFiles.Count - $errors.Count) -ForegroundColor Blue -NoNewline
            Write-Host " ACLs successfully, failed to set " -NoNewline
            Write-Host $errors.Count -ForegroundColor Blue -NoNewline
            Write-Host " ACLs. Total time " -NoNewline
            Write-Host $totalTime -ForegroundColor Blue -NoNewline
            Write-Host " seconds. Errors:"
        }
        Write-Host
        
        # Print first $maxErrorsToShow errors
        $errors.GetEnumerator() | Select-Object -First $maxErrorsToShow | ForEach-Object {
            Write-Host "  $($_.Key): " -NoNewline
            Write-Host $_.Value -ForegroundColor Red
        }

        # Add a note if there are more errors
        if ($errors.Count -gt $maxErrorsToShow) {
            Write-Host "  ... and " -NoNewline
            Write-Host ($errors.Count - $maxErrorsToShow) -ForegroundColor Red -NoNewline
            Write-Host " more errors"
            Write-Host
        }
        
        # Save all errors to a JSON file
        ConvertTo-Json $errors | Out-File "errors.json"
        Write-Host "  Full list of errors has been saved in " -NoNewline
        Write-Host "errors.json" -ForegroundColor Blue
        
        Write-Host
    } else {
        Write-Host $doneStatus -ForegroundColor Green -NoNewline
        Write-Host "Set " -NoNewline
        Write-Host $allFiles.Count -ForegroundColor Blue -NoNewline
        Write-Host " ACLs in " -NoNewline
        Write-Host $totalTime -ForegroundColor Blue -NoNewline
        Write-Host " seconds"
    }
}
