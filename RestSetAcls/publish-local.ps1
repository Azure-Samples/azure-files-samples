$RepoPath = "$PSScriptRoot\LocalRepo"

Write-Host "Creating $RepoPath" -ForegroundColor White
New-Item -Path $RepoPath -ItemType Directory -Force | Out-Null

Write-Host "Registering LocalRepo with $RepoPath" -ForegroundColor White
Register-PSRepository -Name LocalRepo -SourceLocation $RepoPath -InstallationPolicy Trusted

Write-Host "Publishing dependencies in LocalRepo" -ForegroundColor White
$dependencies = @("Az.Storage")
foreach ($dependency in $dependencies) {
    Write-Host "Publishing $dependency to LocalRepo" -Fore Gray
    $module = Get-Module $dependency
    $modulePath = Get-Item $module.Path
    Publish-Module -Path $modulePath.Directory.FullName -Repository LocalRepo
}

Write-Host "Publishing RestSetAcls to LocalRepo" -ForegroundColor White
Publish-Module -Path $PSScriptRoot/RestSetAcls -Repository LocalRepo
