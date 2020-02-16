param(
    [string]$EncodedForwardingRules,
    [string]$OdjBlob,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

Import-Module `
        -Name .\HybridManagement.psd1 `
        -ArgumentList @{ 
            SkipPowerShellGetCheck = $true;
            SkipAzPowerShellCheck = $true;
            SkipDotNetFrameworkCheck = $true
        }
        
Invoke-Expression -Command "using module HybridManagement"

Get-OSFeature | `
    Where-Object { $_.Name -eq "DNS" -and !$_.Installed } | `
    Install-OSFeature

Join-OfflineMachine `
        -OdjBlob $OdjBlob `
        -WindowsPath $env:windir

$forwardingRules = [DnsForwardingRuleSet]::new((ConvertFrom-EncodedJson -String $EncodedForwardingRules))
Push-DnsServerConfiguration -DnsForwardingRuleSet $forwardingRules

if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}