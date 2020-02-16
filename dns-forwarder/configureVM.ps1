param(
    [string]$EncodedForwardingRules,
    [string]$OdjBlob,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

Import-Module .\AzureFilesArmUtilities.psm1

Install-WindowsFeature `
        -Name "DNS" `
        -WarningAction SilentlyContinue | `
    Out-Null

$path = Get-Location | Select-Object -ExpandProperty Path
$dnsForwarderOdj = [System.IO.Path]::Combine($path, "dnsforwarder.odj")
$djOutput = [System.IO.Path]::Combine($path, "djOutput.txt")

Write-OdjBlob -OdjBlob $OdjBlob -Path $dnsForwarderOdj
Join-WindowsMachine `
    -OdjBlobPath $dnsForwarderOdj `
    -WindowsPath $env:windir `
    -JoinOutputPath $djOutput

$forwardingRules = ConvertFrom-EncodedJson -String $EncodedForwardingRules
foreach($forwardRule in $forwardingRules.DnsForwardingRules) {
    $zoneName = Get-DnsServerZone | `
        Where-Object { $_.ZoneName -eq $forwardRule.domainName }
    
    if ($null -eq $zoneName) {
        Add-DnsServerConditionalForwarderZone `
            -Name $forwardRule.domainName `
            -MasterServers $forwardRule.masterServers
    }
}

Clear-DnsClientCache
Clear-DnsServerCache `
    -Confirm:$false `
    -Force

if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}