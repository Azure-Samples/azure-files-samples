
Powershell

# Install public network module in which we have added Custom routes parameter or latest PS module
Install-Module -Name Az -AllowClobber

#Below Setup parameters need to be updated as per Customer's settings.
$SubscriptionName = "<YOUR SUBSCRIPTION NAME>"
$RG = "<YOUR RESOURCE GROUP NAME>"
$Location = "<YOUR AZURE REGION E.g. Central Us>"
$GWName = "<YOUR GATEWAY NAME E.g. default in Template is VnetGw>"
$NewCustomRoutes = "<YOUR STORAGE ACCOUNT CIDR ADDRESS E.g. 192.168.9.0/24>"

#Login and select subscription
Login-AzAccount
Get-AzSubscription
Select-AzSubscription -SubscriptionName $SubscriptionName

# Get existing Virtual network gateway created using 'Azure Files - Point-to-Site VPN Tunnel' document @https://github.com/Azure-Samples/azure-files-samples/tree/master/point-to-site-vpn-azure-files
$Gateway = Get-AzVirtualNetworkGateway -ResourceGroupName $RG -Name $GWName

# Update the custom routes / new Storage acccount IPs/ subnets on Gateway 
Set-AzVirtualNetworkGateway -VirtualNetworkGateway $actual -VpnClientProtocol IkeV2 -CustomRoute $NewCustomRoutes

# Customer needs to redownload VpnClient package. This will provide the SAS Url, customer can download and install VpnClient package from that. This will update the routes on VpnClient machine.
$packageUrl = Get-AzVpnClientPackage -ResourceGroupName $RG -VirtualNetworkGatewayName $GWName -ProcessorArchitecture Amd64