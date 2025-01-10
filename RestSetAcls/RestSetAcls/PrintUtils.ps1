function Ask([Parameter(Mandatory = $false)][string] $question) {
    while ($true) {
        $yn = Read-Host "${question} [Y/n]"
        $yn = $yn.Trim().ToLower()
        if ($yn -eq 'n') {
            return $false
        }
        elseif ($yn -eq '' -or $yn -eq 'y') {
            return $true
        }
        Write-Host "Invalid answer '$yn'. Answer with either 'y' or 'n'" -ForegroundColor Red
    }
}

function Get-IsPowerShellIse {
    return $host.Name -eq "Windows PowerShell ISE Host"
}

function Get-SpecialCharactersPrintable {
    # Windows Terminal supports it
    if ($env:WT_SESSION) {
        return $true
    }

    # PowerShell 6+ supports it
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return $true
    }

    # Older versions don't
    return $false
}

function Write-DoneHeader {
    if (Get-SpecialCharactersPrintable) { 
        $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
        Write-Host "($checkmark) Done: " -ForegroundColor Green -NoNewline
    }
    else {
        Write-Host "Done: " -ForegroundColor Green -NoNewline
    }
}

function Write-PartialHeader {
    if (Get-SpecialCharactersPrintable) { 
        $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
        Write-Host "($cross) Partial: " -ForegroundColor Yellow -NoNewline
    }
    else {
        Write-Host "Partial: " -ForegroundColor Yellow -NoNewline
    }
}

function Write-FailedHeader {
    if (Get-SpecialCharactersPrintable) { 
        $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
        Write-Host "($cross) Failed: " -ForegroundColor Red -NoNewline
    }
    else {
        Write-Host "Failed: " -ForegroundColor Red -NoNewline
    }
}

function Write-WarningHeader {
    if (Get-SpecialCharactersPrintable) { 
        $warning = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("26A0", 16))
        Write-Host "($warning) Warning: " -ForegroundColor Yellow -NoNewline
    }
    else {
        Write-Host "Warning: " -ForegroundColor Yellow -NoNewline
    }
}

function Write-Failure {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Overview,
        
        [Parameter(Mandatory = $false)]
        [string]$Details = $null
    )

    Write-FailedHeader
    Write-Host $Overview -ForegroundColor Red
    if (-not [string]::IsNullOrWhiteSpace($Details)) {
        Write-Host
        Write-Host $Details -ForegroundColor Red
    }
}

