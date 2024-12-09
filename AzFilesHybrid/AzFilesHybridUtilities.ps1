function Write-TestingPassedPSStyle(
    [Parameter(Mandatory=$false, Position=0)]
    [int]$Indents = 1
) {
    $indentation = "`t" * $Indents
    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    Write-Host "$($PSStyle.Foreground.BrightGreen)${indentation}($checkmark) Passed$($PSStyle.Reset)"
}

function Write-TestingFailed(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message,
    [Parameter(Mandatory=$false, Position=1)]
    [int]$ResultIndent = 1,
    [Parameter(Mandatory=$false, Position=2)]
    [int]$ErrorIndent = 1
) {
    $resultIndentation = "`t" * $ResultIndent
    $errorIndentation = "`t" * $ErrorIndent
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2715", 16))
    Write-Host "$($PSStyle.Foreground.BrightRed)${resultIndentation}($cross) Failed$($PSStyle.Reset)"
    Write-Host "${errorIndentation}$($PSStyle.Foreground.BrightRed)ERROR$($PSStyle.Reset): $Message"
}

function Write-TestingWarning(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message,
    [Parameter(Mandatory=$false, Position=1)]
    [int]$Indents = 1
) {
    $indentation = "`t" * $Indents
    $warningIcon = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("26A0", 16))
    [string]$warning = "$($PSStyle.Foreground.BrightYellow)WARNING$($PSStyle.Reset)"
    Write-Host "$($PSStyle.Foreground.BrightYellow)${indentation}($warningIcon ) Partial$($PSStyle.Reset)"
    Write-Host "${indentation}${warning}: $Message"
}