$repoName = "LocalRepo"
$repoPath = "$PSScriptRoot\bin\LocalRepo"
$moduleName = "RestSetAcls"
$psd1 = "$PSScriptRoot\RestSetAcls\RestSetAcls.psd1"

function Get-Dependencies {
    return (Import-PowershellDataFile -Path $psd1).RequiredModules.ModuleName
}

function Publish-Local {
    $dependencies = Get-Dependencies

    Write-Host "Creating $RepoPath" -ForegroundColor White
    New-Item -Path $RepoPath -ItemType Directory -Force | Out-Null
    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nRegistering $repoName with $RepoPath" -ForegroundColor White
    Register-PSRepository -Name $repoName -SourceLocation $RepoPath -InstallationPolicy Trusted
    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nPublishing $moduleName and dependencies in $repoName" -ForegroundColor White
    # Check if dependencies are installed
    foreach ($dependency in $dependencies) {
        $modules = Get-Module $dependency -ListAvailable
        if ($modules.Length -eq 0) {
            throw "Module $dependency not found in the current environment. Please run .\init.ps1 first."
        }
    }

    # Publish dependencies
    foreach ($dependency in $dependencies) {
        $module = $(Get-Module $dependency -ListAvailable)[0]
        Write-Host "Publishing $dependency v$($module.Version) to $repoName" -ForegroundColor Gray
        $modulePath = Get-Item $module.Path
        Publish-Module -Path $modulePath.Directory.FullName -Repository $repoName
    }

    # Publish main module
    Write-Host "Publishing $moduleName to $repoName" -ForegroundColor Gray
    Publish-Module -Path $PSScriptRoot/$moduleName -Repository $repoName

    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nUnloading currently loaded modules" -ForegroundColor White
    Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
    foreach ($dependency in $dependencies) {
        Remove-Module -Name $dependency -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nInstalling $moduleName from $repoName" -ForegroundColor White
    Install-Module -Name $moduleName -Repository $repoName -Force
    Write-Host "Done" -ForegroundColor Gray
}

function Uninstall-LocalRepoModule {
    param (
        [string]$moduleName,
        [string]$repoName
    )
    Get-InstalledModule -Name $moduleName | Where-Object { $_.Repository -eq $repoName } | ForEach-Object {
        Write-Host "Uninstalling $moduleName v$($_.Version) from $repoName" -ForegroundColor Gray
        Uninstall-Module -Name $moduleName -RequiredVersion $_.Version -Force
    }
}

function Unpublish-Local {
    $dependencies = Get-Dependencies

    Write-Host "Unloading modules" -ForegroundColor White
    Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
    $dependencies | ForEach-Object { Remove-Module -Name $_ -Force -ErrorAction SilentlyContinue }
    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nUninstalling $moduleName" -ForegroundColor White
    Uninstall-LocalRepoModule -moduleName $moduleName -repoName $repoName
    Write-Host "Done" -ForegroundColor Gray

    Write-Host "`nUnregistering LocalRepo" -ForegroundColor White
    Unregister-PSRepository -Name LocalRepo

    Write-Host "`nRemoving LocalRepo" -ForegroundColor White
    Remove-Item -Path $RepoPath -Recurse -Force
    Write-Host "Done" -ForegroundColor Gray
}

function Publish-PSGallery {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "PowerShell Gallery API Key")]
        [string]$apiKey
    )

    Write-Host "Running tests" -ForegroundColor White -NoNewline
    Invoke-Pester -Path $PSScriptRoot\test -Output Minimal
    Write-Host

    # This will also run Test-ModuleManifest
    Write-Host "Publishing" -ForegroundColor White
    Publish-Module -Path $PSScriptRoot\RestSetAcls -NuGetApiKey $apiKey -WhatIf:$WhatIfPreference
    Write-Host "Done" -ForegroundColor Green
}
