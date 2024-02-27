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

    $directory = Get-AzStorageFile -Context $Context -ShareName $FileShareName -Path $FilePath
    
    Write-Host "Step 1: Finding all files" -ForegroundColor Blue
    $ProgressPreference = "SilentlyContinue"
    $i = 0
    $allFiles = Get-AzureFilesRecursive -Context $context -Directory $directory | ForEach-Object {
        $i++
        Write-Debug $_
        Write-Host "`rFound " -ForegroundColor DarkGray -NoNewline
        Write-Host $i -ForegroundColor Yellow -NoNewline
        Write-Host " files and folders" -ForegroundColor DarkGray -NoNewline
        $_
    }
    Write-Host "`n"
    $ProgressPreference = "Continue"

    Write-Host "Step 2: Setting ACLs" -ForegroundColor Blue
    $startTime = Get-Date
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
        # Write-Host "Setting ACL for $fileFullPath" -ForegroundColor DarkGray
        Set-AzureFilesAcl -File $file.File -SddlPermission $SddlPermission
        # Start-Sleep -Milliseconds 500
    }
    Write-Progress -Activity "Setting ACLs" -Status "Done" -Completed

    Write-Host "Done" -ForegroundColor Green
    Write-Host "Total time: $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)) seconds" -ForegroundColor DarkGray
}
