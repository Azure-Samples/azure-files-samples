$repoName = "LocalRepo"
$repoPath = "$PSScriptRoot\bin\LocalRepo"
$moduleName = "RestSetAcls"
$psd1 = Import-PowershellDataFile -Path "$PSScriptRoot\RestSetAcls\RestSetAcls.psd1"
$dependencies = $psd1.RequiredModules.ModuleName

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