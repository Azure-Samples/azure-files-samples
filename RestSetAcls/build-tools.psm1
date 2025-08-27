#region Build
function Get-PowerShellFiles {
    Get-ChildItem $PSScriptRoot -Exclude bin `
    | Get-ChildItem -Recurse -Include *.psd1, *.psm1, *.ps1
}

function Lint {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path = "$PSScriptRoot\RestSetAcls"
    )

    Invoke-ScriptAnalyzer -Path $Path -Settings $PSScriptRoot\PSScriptAnalyzerSettings.ps1 -Recurse -Outvariable issues
    $errors = $issues.Where({ $_.Severity -eq 'Error' })
    $warnings = $issues.Where({ $_.Severity -eq 'Warning' })
    $infos = $issues.Where({ $_.Severity -eq 'Information' })

    if ($errors.Count -gt 0 -or $warnings.Count -gt 0) {
        Write-Error "There were $($errors.Count) errors, $($warnings.Count) warnings and $($infos.Count) infos total." -ErrorAction Stop
    }
    else {
        Write-Output "There were $($errors.Count) errors, $($warnings.Count) warnings and $($infos.Count) infos total."
    }
}

function Test-Format {
    $failed = $false

    foreach ($file in Get-PowerShellFiles) {
        $content = Get-Content -Path $file -Raw
        $formatted = Invoke-Formatter -ScriptDefinition $content -Settings $PSScriptRoot\PSScriptAnalyzerSettings.ps1
        
        if ($content -ne $formatted) {
            Write-Host "File $($file.FullName) is not formatted correctly." -ForegroundColor Red
            $failed = $true
        }
    }

    if ($failed) {
        Write-Error "There were formatting issues." -ErrorAction Stop
    }
    else {
        Write-Output "There were no formatting issues."
    }
}

function Format {
    foreach ($file in Get-PowerShellFiles) {
        $content = Get-Content -Path $file -Raw
        $formatted = Invoke-Formatter -ScriptDefinition $content -Settings $PSScriptRoot\PSScriptAnalyzerSettings.ps1
        
        if ($content -ne $formatted) {
            Write-Host "Reformatting $file" -ForegroundColor Blue
            Set-Content -Path $file -Value $formatted            
        }
        else {
            Write-Host "File $($file.FullName) is already formatted correctly." -ForegroundColor Green
        }
    }
}

function Test {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path = "$PSScriptRoot\test\unit",

        [Parameter(ValueFromRemainingArguments = $true)]
        [psobject[]]$RemainingArgs
    )

    $container = New-PesterContainer -Path $Path

    # Build object we can splat into Invoke-Pester
    # See https://stackoverflow.com/a/71073148/918389
    $params = foreach ($arg in $RemainingArgs) {
        if ($arg.StartsWith('-')) {
            $prop = [psnoteproperty]::new('<CommandParameterName>', $arg)
            $arg.PSObject.Properties.Add($prop)
        }
        $arg
    }

    Invoke-Pester -Container $container -Output Detailed @params
}

# https://stackoverflow.com/a/34383413
function Convert-PSObjectToHashtable
{
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )

    process
    {
        if ($null -eq $InputObject) {
            return $null
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $collection = @(
                foreach ($object in $InputObject) {
                    Convert-PSObjectToHashtable $object
                }
            )

            Write-Output -NoEnumerate $collection
        }
        elseif ($InputObject -is [psobject])
        {
            $hash = @{}

            foreach ($property in $InputObject.PSObject.Properties)
            {
                $hash[$property.Name] = (Convert-PSObjectToHashtable $property.Value).PSObject.BaseObject
            }

            $hash
        }
        else
        {
            $InputObject
        }
    }
}

function Test-Integration {
    param (
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile = "$PSScriptRoot\test\integration\config.json",

        [Parameter(ValueFromRemainingArguments = $true)]
        [psobject[]]$RemainingArgs
    )
    # Check if the config file exists
    if (-not (Test-Path -Path $ConfigFile)) {
        Write-Error "Config file not found: $ConfigFile" -ErrorAction Stop
    }

    # Parse config into Pester container
    $config = Get-Content -Raw $ConfigFile | ConvertFrom-Json | Convert-PSObjectToHashtable

    $container = New-PesterContainer -Path $PSScriptRoot\test\integration -Data @{ InputConfig = $config }

    # Build object we can splat into Invoke-Pester
    # See https://stackoverflow.com/a/71073148/918389
    $params = foreach ($arg in $RemainingArgs) {
        if ($arg.StartsWith('-')) {
            $prop = [psnoteproperty]::new('<CommandParameterName>', $arg)
            $arg.PSObject.Properties.Add($prop)
        }
        $arg
    }

    Invoke-Pester -Container $container -Output Detailed @params
}

function Test-Manifest {
    Test-ModuleManifest -Path $PSScriptRoot\RestSetAcls\RestSetAcls.psd1
}

function Test-All {
    Test
    Lint
    Test-Manifest
    Test-Format
}

function New-Docs {
    Import-Module -Name $PSScriptRoot\RestSetAcls\RestSetAcls.psd1 -Force
    New-MarkdownHelp -Module RestSetAcls -OutputFolder $PSScriptRoot\docs -Force
}
#endregion Build

#region Publish
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
    Install-Module -Name $moduleName -Repository $repoName -AllowClobber -Force
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
    Test
    Write-Host

    # This will also run Test-ModuleManifest
    Write-Host "Publishing" -ForegroundColor White
    Publish-Module -Path $PSScriptRoot\RestSetAcls -NuGetApiKey $apiKey -WhatIf:$WhatIfPreference
    Write-Host "Done" -ForegroundColor Green
}
#endregion Publish
