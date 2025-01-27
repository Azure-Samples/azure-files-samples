function Test-Manifest {
    Test-ModuleManifest -Path $PSScriptRoot\AzFilesHybrid\AzFilesHybrid.psd1
}

function Publish-PSGallery {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "PowerShell Gallery API Key")]
        [string]$apiKey
    )

    Write-Host "Testing manifest" -ForegroundColor White -NoNewline
    Test-Manifest
    Write-Host

    # This will also run Test-ModuleManifest
    Write-Host "Publishing" -ForegroundColor White
    Publish-Module -Path $PSScriptRoot\AzFilesHybrid -NuGetApiKey $apiKey -WhatIf:$WhatIfPreference
    Write-Host "Done" -ForegroundColor Green
}