[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory=$true, HelpMessage="PowerShell Gallery API Key")]
    [string]$apiKey
)


Write-Host "Running tests" -ForegroundColor White -NoNewline
Invoke-Pester -Path $PSScriptRoot\test -Output Minimal
Write-Host

# This will also run Test-ModuleManifest
Write-Host "Publishing" -ForegroundColor White
Publish-Module -Path $PSScriptRoot\RestSetAcls -NuGetApiKey $apiKey -WhatIf:$WhatIfPreference
