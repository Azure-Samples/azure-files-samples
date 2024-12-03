function Write-FailedPSStyle(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$message
) {
    [string]$redFailed = "`t$($PSStyle.Foreground.BrightRed)FAILED$($PSStyle.Reset)"
    Write-Host "${redFailed}: $message"
}

function Write-WarningPSStyle(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$message
) {
    [string]$warning = "`t$($PSStyle.Foreground.BrightYellow)WARNING$($PSStyle.Reset)"
    Write-Host "${warning}: $message"
}