function Get-PowerShellFiles {
    Get-ChildItem $PSScriptRoot -Exclude bin `
    | Get-ChildItem -Recurse -Include *.psd1, *.psm1, *.ps1
}

function Lint {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path = "$PSScriptRoot\RestSetAcls"
    )

    Invoke-ScriptAnalyzer -Path $Path -ExcludeRule PSAvoidUsingWriteHost -Recurse -Outvariable issues
    $errors = $issues.Where({ $_.Severity -eq 'Error' })
    $warnings = $issues.Where({ $_.Severity -eq 'Warning' })
    if ($errors) {
        Write-Error "There were $($errors.Count) errors and $($warnings.Count) warnings total." -ErrorAction Stop
    }
    else {
        Write-Output "There were $($errors.Count) errors and $($warnings.Count) warnings total."
    }
}

function Test-Format {
    $failed = $false

    foreach ($file in Get-PowerShellFiles) {
        $content = Get-Content -Path $file -Raw
        $formatted = Invoke-Formatter -ScriptDefinition $content
        
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
        $formatted = Invoke-Formatter -ScriptDefinition $content
        
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
    Invoke-Pester -Path $PSScriptRoot\test -Output Detailed
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