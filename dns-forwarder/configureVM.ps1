param(
    [string]$DomainName,
    [string]$RootDomainName,
    [string]$OdjBlob,
    [string[]]$OnPremDnsServers,
    [string]$StorageEndpoint,
    [string]$PrivateDnsIp,
    [string]$TempUser,
    [switch]$SkipUserDisable
)

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

$domainZoneName = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $RootDomainName }
if ($null -eq $domainZoneName) {
    Add-DnsServerConditionalForwarderZone `
        -Name $RootDomainName `
        -MasterServers $OnpremDnsServers
}

$storageZoneName = Get-DnsServerZone | Where-Object { $_.ZoneName -eq $StorageEndpoint }
if ($null -eq $storageZoneName) {
    Add-DnsServerConditionalForwarderZone `
        -Name $StorageEndpoint `
        -MasterServers $PrivateDnsIp
}

ipconfig.exe /renew | Out-Null 
ipconfig.exe /flushdns | Out-Null

if (!$SkipUserDisable) {
    Disable-LocalUser -Name $TempUser
}