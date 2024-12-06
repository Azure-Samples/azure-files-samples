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

function Write-TestingPassedPSStyle(
    [Parameter(Mandatory=$false, Position=0)]
    [int]$Indents = 4
) {
    $indentation = "`t" * $Indents
    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightGreen)${indentation}($checkmark) Passed$($PSStyle.Reset)"
}

function Write-TestingFailed(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message,
    [Parameter(Mandatory=$false, Position=1)]
    [int]$ResultIndent = 4,
    [Parameter(Mandatory=$false, Position=2)]
    [int]$ErrorIndent = 4
) {
    $resultIndentation = "`t" * $ResultIndent
    $errorIndentation = "`t" * $ErrorIndent
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2715", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightRed)${resultIndentation}($cross) Failed$($PSStyle.Reset)"
    Write-Host "${errorIndentation}$($PSStyle.Foreground.BrightRed)ERROR$($PSStyle.Reset): $Message"
}

function Write-TestingWarningPSStyle(
    [Parameter(Mandatory=$false, Position=0)]
    [int]$Indents = 2
) {
    $indentation = "`t" * $Indents
    $warning = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("26A0", 16))
    Write-Host "`r$($PSStyle.Foreground.BrightYellow)${indentation}($warning ) Partial$($PSStyle.Reset)"
}