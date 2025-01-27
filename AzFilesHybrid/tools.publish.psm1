$checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))

function Get-Hashes {
    Get-ChildItem $PSScriptRoot\AzFilesHybrid -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object -Property Path, Hash    
}

function Test-Signatures {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Path to the folder containing files to check signatures")]
        [string]$folderPath
    )

    if (-not (Test-Path -Path $folderPath)) {
        throw "The path $folderPath does not exist."
    }

    $files = Get-ChildItem -Path $folderPath -Recurse -File

    foreach ($file in $files) {
        try {
            $signature = Get-AuthenticodeSignature -FilePath $file.FullName
            if ($signature.Status -ne 'Valid') {
                throw "The file $($file.FullName) does not have a valid signature"
            }
            if (($signature.SignerCertificate.Thumbprint -ne 'C2048FB509F1C37A8C3E9EC6648118458AA01780') -or 
                ($signature.SignerCertificate.Subject -ne 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US')) {
                throw "The file $($file.FullName) is not signed by the expected certificate"
            }
        } catch {
            throw "Error checking signature for file $($file.FullName): $_"
        }
    }

    Write-Host "$($PSStyle.Foreground.BrightGreen)($checkmark)$($PSStyle.Reset) All $($PSStyle.Foreground.Cyan)$($files.Count)$($PSStyle.Reset) files have valid signatures"
}

function Test-Release {
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the folder containing release files")]
        [string]$folderPath
    )
    Write-Host "Checking release" -ForegroundColor White
    $manifestPath = Join-Path -Path $folderPath -ChildPath "AzFilesHybrid.psd1"

    # Check 1: module manifest is present
    if (-not (Test-Path -Path $manifestPath)) {
        throw "Could not find module manifest AzFilesHybrid.psd1"
    }
    Write-Host "$($PSStyle.Foreground.BrightGreen)($checkmark)$($PSStyle.Reset) Found module manifest AzFilesHybrid.psd1"

    # Check 2: read module version from manifest
    $moduleManifest = Import-PowerShellDataFile $manifestPath
    $version = $moduleManifest.ModuleVersion.ToString()
    Write-Host "$($PSStyle.Foreground.BrightGreen)($checkmark)$($PSStyle.Reset) Extracted version from module manifest $($PSStyle.Foreground.Cyan)$version$($PSStyle.Reset)"

    # Check 3: is release is signed?
    Test-Signatures -folderPath $folderPath

    # Check 4: is file is valid?
    Test-ModuleManifest -Path $manifestPath -ErrorAction Stop | Out-Null
    Write-Host "$($PSStyle.Foreground.BrightGreen)($checkmark)$($PSStyle.Reset) Manifest file is valid"
}

function Import-SignedRelease {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Path to the signed release zip file")]
        [string]$zipFilePath
    )

    $workingDir = "$PSScriptRoot\bin\releases"
    $tempFolderPath = Join-Path -Path $workingDir -ChildPath "temp"
    if (Test-Path -Path $tempFolderPath) {
        Remove-Item -Path $tempFolderPath -Recurse -Force
    }
    Expand-Archive -Path $zipFilePath -DestinationPath $tempFolderPath -Force

    Test-Release $tempFolderPath

    # If all checks pass, move from temp to release folder
    $destinationPath = Join-Path -Path $workingDir -ChildPath "$version/AzFilesHybrid"
    if (Test-Path $destinationPath) {
        Remove-Item -Path $destinationPath -Recurse -Force
    }
    New-Item -Type Directory -Path $destinationPath -Force | Out-Null
    Move-Item -Path "$tempFolderPath\*" -Destination $destinationPath -Force
    Remove-Item $tempFolderPath
    Write-Host "`nImported release to $($PSStyle.Foreground.Cyan)$(Resolve-Path -Relative $destinationPath)$($PSStyle.Reset)"
}

function Publish-PSGallery {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Version to release")]
        [string]$version,

        [Parameter(Mandatory = $true, HelpMessage = "PowerShell Gallery API Key")]
        [string]$apiKey
    )
    $releasePath = "$PSScriptRoot\bin\releases\$version\AzFilesHybrid"

    if (-not (Test-Path $releasePath)) {
        throw "The release folder $releasePath does not exist."
    }

    Test-Release $releasePath

    Write-Host "`nPublishing" -ForegroundColor White
    Publish-Module -Path $PSScriptRoot\release\$version\AzFilesHybrid -NuGetApiKey $apiKey -WhatIf:$WhatIfPreference
    Write-Host "Done" -ForegroundColor Green
}
