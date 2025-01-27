function Write-TestingPassed(
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
    [bool]$IsUnexpected = 0
) {
    [string] $eType = $IsUnexpected ? "Unexpected" : "Failed";
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2715", 16))
    Write-Host "$($PSStyle.Foreground.BrightRed)`t($cross) $eType$($PSStyle.Reset)"
    Write-Host "`t$($PSStyle.Foreground.BrightRed)ERROR$($PSStyle.Reset): $Message"
}


function Write-TestingWarning(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Message
) {
    $warningIcon = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("26A0", 16))
    [string]$warning = "$($PSStyle.Foreground.BrightYellow)WARNING$($PSStyle.Reset)"
    Write-Host "$($PSStyle.Foreground.BrightYellow)`t($warningIcon ) Partial$($PSStyle.Reset)"
    Write-Host "`t${warning}: $Message"
}