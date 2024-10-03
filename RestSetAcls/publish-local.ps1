$repoName = "LocalRepo"
$RepoPath = "$PSScriptRoot\bin\LocalRepo"
$moduleName = "RestSetAcls"
$psd1 = Import-PowershellDataFile -Path "$PSScriptRoot\RestSetAcls\RestSetAcls.psd1"
$dependencies = $psd1.RequiredModules.ModuleName

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
