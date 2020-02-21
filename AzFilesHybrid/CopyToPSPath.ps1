$psModPath = $env:PSModulePath.Split(";")[0]
if (!(Test-Path -Path $psModPath)) {
    New-Item -Path $psModPath -ItemType Directory | Out-Null
}

$psdFile = Import-PowerShellDataFile -Path .\AzFilesHybrid.psd1
$desiredModulePath = "$psModPath\AzFilesHybrid\$($psdFile.ModuleVersion)\"
if (!(Test-Path -Path $desiredModulePath)) {
    New-Item -Path $desiredModulePath -ItemType Directory | Out-Null
}

Copy-Item -Path ".\AzFilesHybrid.psd1" -Destination $desiredModulePath
Copy-Item -Path ".\AzFilesHybrid.psm1" -Destination $desiredModulePath