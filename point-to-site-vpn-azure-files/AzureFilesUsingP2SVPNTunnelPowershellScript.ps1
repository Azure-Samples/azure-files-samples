
Powershell

# Install public network module in which we have added Custom routes parameter ot latest PS module
Install-Module -Name Az -AllowClobber

#Setup
$VNetName  = "Vnet"
$FESubName = "FrontEnd"
$BESubName = "Backend"
$GWSubName = "GatewaySubnet"
$VNetPrefix = "192.168.0.0/16"
$GWSubPrefix = "192.168.200.0/24"
$VPNClientAddressPool = "172.16.201.0/24"
$RG = "TestRG"
$Location = "Central Us"
$DNS = "10.1.1.3"
$GWName = "VnetGw"
$GWIPName = "VnetPip"
$GWIPconfName = "gwipconf"
$CustomRoutes = "192.168.10.0/24"
$NewCustomRoutes = "192.168.9.0/24"

#Login and select subscription
Login-AzAccount
Get-AzSubscription
Select-AzSubscription -SubscriptionName "Reshmi"

# Create Resource group
New-AzResourceGroup -Name $RG -Location $Location

# Create VNet
$gwsub = New-AzVirtualNetworkSubnetConfig -Name $GWSubName -AddressPrefix $GWSubPrefix
New-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RG -Location $Location -AddressPrefix $VNetPrefix -Subnet $fesub, $besub, $gwsub -DnsServer $DNS
$vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $RG
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "GatewaySubnet" -VirtualNetwork $vnet

# Client root certificate 
$P2SRootCertName = "P2SRootCert.cer"
$filePathForCert = "C:\Desktop\P2SRootCert.cer" #Path to the Root certificate
$cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2($filePathForCert)
$CertBase64 = [system.convert]::ToBase64String($cert.RawData)
$p2srootcert = New-AzVpnClientRootCertificate -Name $P2SRootCertName -PublicCertData $CertBase64

# Create P2S VPN Gateway
$pip = New-AzPublicIpAddress -Name $GWIPName -ResourceGroupName $RG -Location $Location -AllocationMethod Dynamic
$ipconf = New-AzVirtualNetworkGatewayIpConfig -Name $GWIPconfName -Subnet $subnet -PublicIpAddress $pip
New-AzVirtualNetworkGateway -Name $GWName -ResourceGroupName $RG -Location $Location -IpConfigurations $ipconf -GatewayType Vpn -VpnType RouteBased -EnableBgp $false -GatewaySku VpnGw1 172.16.201.0/24

New-AzVirtualNetworkGateway -ResourceGroupName $RG -name $GWName -location $location -IpConfigurations $ipconf -GatewayType Vpn -VpnType RouteBased -EnableBgp $false -GatewaySku VpnGw1 -VpnClientAddressPool -VpnClientProtocol SSTP -VpnClientRootCertificates $p2srootcert -CustomRoute $CustomRoutes
 
$Gateway = Get-AzVirtualNetworkGateway -ResourceGroupName $RG -Name $GWName

# Download VpnClient package, this will provide the SAS Url, you can download and install VpnClient package from that.
$packageUrl = Get-AzVpnClientPackage -ResourceGroupName $RG -VirtualNetworkGatewayName $GWName -ProcessorArchitecture Amd64

# Update the custom routes on Gateway and then redownload VpnClient package
Set-AzVirtualNetworkGateway -VirtualNetworkGateway $actual -VpnClientProtocol IkeV2 -CustomRoute $NewCustomRoutes
$packageUrl = Get-AzVpnClientPackage -ResourceGroupName $RG -VirtualNetworkGatewayName $GWName -ProcessorArchitecture Amd64