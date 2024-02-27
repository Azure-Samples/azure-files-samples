function Get-AzureFilesRecursive {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object[]]$Directory,

        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,

        [Parameter(Mandatory=$false)]
        [string]$Path = ""
    )

    foreach ($file in $directory) {
        $fullPath = "${path}$($file.Name)"
        $isDirectory = $false

        $file.Context = $context

        if ($file.GetType().Name -eq "AzureStorageFileDirectory") {
            $isDirectory = $true
            $fullPath += "/"

            # Recurse on subdirectory
            $subdirectory = Get-AzStorageFile -Directory $file.CloudFileDirectory
            if ($null -ne $subdirectory) {
                Get-AzureFilesRecursive -Context $context -Directory $subdirectory -Path $fullPath
            }
        }

        Write-Output @{
            IsDirectory = $isDirectory
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
        )
    } else {
        $file = [Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile]$File
        $file.ShareFileClient.SetHttpHeaders(
            $null, # newSize
            $null, # httpHeaders
            $null, # smbProperties
            $SddlPermission # filePermission
        )
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
        [switch]$Recursive
    )

    Write-Host "Step 1: Finding all files" -ForegroundColor White
    $startTime = Get-Date

    # Get root directory
    try {
        $directory = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath -ErrorAction Stop
    } catch {
        Write-Host "(✗) Failed: " -ForegroundColor Red -NoNewline
        Write-Host "Failed to read root directory"
        Write-Host
        Write-Host $_.Exception.Message -ForegroundColor Red
        return
    }
    
    # Recursively find all files under the root directory
    $ProgressPreference = "SilentlyContinue"
    $i = 0
    $allFiles = Get-AzureFilesRecursive -Context $context -Directory $directory | ForEach-Object {
        $i++
        Write-Debug $_
        Write-Host "`rFound " -ForegroundColor DarkGray -NoNewline
        Write-Host $i -ForegroundColor Blue -NoNewline
        Write-Host " files and folders" -ForegroundColor DarkGray -NoNewline
        $_
    }

    # Print success
    $totalTime = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
    Write-Host "`r(✓) Done: " -ForegroundColor Green -NoNewline
    Write-Host "Found " -NoNewline
    Write-Host $allFiles.Count -ForegroundColor Blue -NoNewline
    Write-Host " files and folders in " -NoNewline
    Write-Host $totalTime -ForegroundColor Blue -NoNewline
    Write-Host " seconds"
    $ProgressPreference = "Continue"
    
    Write-Host

    Write-Host "Step 2: Setting ACLs" -ForegroundColor White
    $startTime = Get-Date
    $errors = @{}
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
    
    # Close the progress bar
    Write-Progress -Activity "Setting ACLs" -Status "Done" -Completed

    $totalTime = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
    if ($errors.Count -eq $allFiles.Count) {
        # Setting ACLs failed for all files; report it.
        Write-Host "(✗) Failed: " -ForegroundColor Red -NoNewline
        Write-Host "Failed to set " -NoNewline
        Write-Host $errors.Count -ForegroundColor Red -NoNewline
        Write-Host " ACLs. Total time " -NoNewline
        Write-Host $totalTime -ForegroundColor Blue -NoNewline
        Write-Host " seconds"
    }
    elseif ($errors.Count -gt 0) {
        # Setting ACLs failed for some, but not all files. In such cases, it may be important
        # to know which files failed. We print the first 10, and put the rest in a JSON file.
        $maxErrorsToShow = 10
        
        Write-Host "(✗) Partial: " -ForegroundColor Yellow -NoNewline
        Write-Host "Set " -NoNewline
        Write-Host $($allFiles.Count - $errors.Count) -ForegroundColor Blue -NoNewline
        Write-Host " ACLs successfully, failed to set " -NoNewline
        Write-Host $errors.Count -ForegroundColor Blue -NoNewline
        Write-Host " ACLs. Total time " -NoNewline
        Write-Host $totalTime -ForegroundColor Blue -NoNewline
        Write-Host " seconds. Errors:"
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
        Write-Host "(✓) Done: " -ForegroundColor Green -NoNewline
        Write-Host "Set " -NoNewline
        Write-Host $allFiles.Count -ForegroundColor Blue -NoNewline
        Write-Host " ACLs in " -NoNewline
        Write-Host $totalTime -ForegroundColor Blue -NoNewline
        Write-Host " seconds"
    }
}
