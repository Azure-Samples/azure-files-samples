param(
    [string]$EncodedForwardingRules,
    [string]$OdjBlob,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

function ConvertFrom-EncodedJson {
    param(
        [string]$String
    )

    $String = $String.
        Replace("*", "`"").
        Replace("<", "[").
        Replace(">", "]").
        Replace("^", "{").
        Replace("%", "}")
    
    return (ConvertFrom-Json -InputObject $String)
}

function Write-OdjBlob {
    param(
        [string]$OdjBlob,
        [string]$Path
    )

    $byteArray = [System.Byte[]]@()
    $byteArray += 255
    $byteArray += 254

    $byteArray += [System.Text.Encoding]::Unicode.GetBytes($OdjBlob)

    $byteArray += 0
    $byteArray += 0

    $writer = [System.IO.File]::Create($Path)
    $writer.Write($byteArray, 0, $byteArray.Length)

    $writer.Close()
    $writer.Dispose()
}

Install-WindowsFeature `
        -Name "DNS" `
        -WarningAction SilentlyContinue | `
    Out-Null

$path = Get-Location | Select-Object -ExpandProperty Path
$dnsForwarderOdj = [System.IO.Path]::Combine($path, "dnsforwarder.odj")
$djOutput = [System.IO.Path]::Combine($path, "djOutput.txt")

Write-OdjBlob -OdjBlob $OdjBlob -Path $dnsForwarderOdj
Invoke-Expression `
        -Command "djoin.exe /requestodj /loadfile `"$dnsForwarderOdj`" /windowspath $($env:windir) /localos" | `
    Out-File -FilePath $djOutput

$forwardingRules = ConvertFrom-EncodedJson -String $EncodedForwardingRules
foreach($forwardRule in $forwardingRules) {
    $zoneName = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $forwardRule.domainName }
    if ($null -eq $zoneName) {
        Add-DnsServerConditionalForwarderZone `
            -Name $forwardRule.domainName `
            -MasterServers $forwardRule.masterServers
    }
}

ipconfig.exe /renew | Out-Null 
ipconfig.exe /flushdns | Out-Null

if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}