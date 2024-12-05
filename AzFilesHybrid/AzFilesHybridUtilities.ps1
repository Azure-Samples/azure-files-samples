function Write-FailedPSStyle(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message,
    [Parameter(Mandatory=$false, Position=1)]
    [int]$Indents = 1
) {
    $indentation = "`t" * $Indents
    [string]$redFailed = "$($PSStyle.Foreground.BrightRed)ERROR$($PSStyle.Reset)"
    Write-Host "${indentation}${redFailed}: $Message"
}

function Write-WarningPSStyle(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message,
    [Parameter(Mandatory=$false, Position=1)]
    [int]$Indents = 1
) {
    $indentation = "`t" * $Indents
    [string]$warning = "$($PSStyle.Foreground.BrightYellow)WARNING$($PSStyle.Reset)"
    Write-Host "${indentation}${warning}: $Message"
}

function Write-TestingPassedPSStyle {
    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightGreen)`t`t($checkmark) Passed$($PSStyle.Reset)"
}

function Write-TestingFailedPSStyle {
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2715", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightRed)`t`t($cross) Failed$($PSStyle.Reset)"
}

function Write-TestingWarningPSStyle {
    $warning = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("26A0", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightYellow)`t`t($warning ) Partial$($PSStyle.Reset)"
}