# Customer Variables
$VNetId = '<YOUR VNET ID COPIED FROM PREVIOUS STEP>' #Found in the VPN Setting configuration
$FileShareHostList = @('<YOUR STORAGE ACCOUNT NAME>.file.core.windows.net') # All Storage Accounts that should use this VPN connection


#Internal Variables
$VPNInstallPath = "$env:APPDATA\Microsoft\Network\Connections\Cm\$VNetId"
$VPNRoutePath = "$env:APPDATA\Microsoft\Network\Connections\Cm\$VNetId\routes.txt"
$VPNDllRoutePath = "$env:APPDATA\Microsoft\Network\Connections\Cm\$VNetId\cmroute.dll"
$VPNPhonebookPath = "$env:APPDATA\Microsoft\Network\Connections\Cm\$VNetId\$VNetId.pbk"
$VPNRouteHeader = '# Custom Azure File Route:'
$VPNRouteHeaderRegex = '# Custom Azure File Route: (\S+)'
[System.Collections.ArrayList]$FileshareIPStringList = @()
[System.Collections.ArrayList]$VPNRouteAddList = @()
[System.Collections.ArrayList]$FileShareResolvedHostList = @()

# Determine if the VPN is installed
if(-not (Test-Path $VPNInstallPath))
{
    throw "The VPN interface with ID $VNetId does not seem to exist as there is no installation at path $VPNInstallPath. Please check to make sure this VPN connection is installed"
}
elseif(-not (Test-Path $VPNRoutePath))
{
    throw "The VPN route path was not found in the path $VPNInstallPath. Please reinstall the VPN connection."
}
elseif(-not (Test-Path $VPNPhonebookPath))
{
    throw "The VPN phonebook path was not found in the path $VPNInstallPath. Please reinstall the VPN connection."
}
elseif(-not (Test-Path $VPNDllRoutePath))
{
    throw "The VPN dll route path was not found in the path $VPNInstallPath. Please reinstall the VPN connection."
}

# Find the IP of each File Share
foreach ($FileShareHost in $FileShareHostList)
{
    Try
    {    
        $FileshareIPQuery = [system.Net.Dns]::GetHostByName($FileShareHost) 
        $FileshareIP = [ipaddress]$fileshareIPQuery.AddressList[0]                
        $FileshareIPString = $FileshareIP.IPAddressToString

        # Check that the File Share IP is not already added
        $FileShareIPIndex = $FileshareIPStringList.IndexOf($FileshareIPString)
        if($FileShareIPIndex -lt 0)
        {
            $FileShareResolvedHostList += $FileShareHost
            $FileshareIPStringList += $FileshareIPString
            $VPNRouteAddList += "ADD $FileshareIPString MASK 255.255.255.255 default METRIC default IF default"
        }
        else
        {
            Write-Warning "$FileShareHost with IP $FileshareIPString is already in the route with another host. Skipping this host"
        }
    }
    Catch    {                    # Remove the host from the list        Write-Warning "Cannot resolve IP address of host $FileShareHost. Skipping this host"    }    
}

# Get all routes from the file 
$AllRouteLines = Get-Content $VPNRoutePath
$StandardRoutes = @()
$AzureFileRewriteRoutes = @()
$RewriteFile = $false

foreach($Route in $AllRouteLines) 
{    Write-Information "Next Route is $Route"    # Capture all Azure Files Marked Routes    if($Route -match $VPNRouteHeaderRegex)
    {        

        # Check to make sure the file share can be found in the route. If not, move on
        if($Matches.Count -lt 2)
        {            Write-Error "The route in the file $VPNRoutePath is malformed. Cannot find the File Share"            continue        }

        # Save file share for this route
        $RouteFileShare = $Matches[1]

        # Split the route into parts to get the IP address
        $RouteLineArray = $Route -split '\s+'        #Check that the Route contains an IP address        if($RouteLineArray.Length -lt 9)        {            # Something is malformed, force rewrite of file            Write-Warning "The route in the file $VPNRoutePath is malformed. It must have a format of \'ADD (IPV4) MASK (IPV4) default METRIC default IF default\'"            $RewriteFile = $true            continue        }        # Find the IP Address and make sure it is correctly formed        Try        {            $ExistingIP = [ipaddress]$RouteLineArray[1]        }        Catch        {                # Something is malformed, force rewrite of file                    Write-Warning "Invalid IP address in the route."            $RewriteFile = $true            continue        }        # Check that the File Share is part of the list to add
        $FileShareHostIndex = $FileShareResolvedHostList.IndexOf($RouteFileShare)
        if($FileShareHostIndex -ge 0)
        {
            # Check to see if the IP is different 
            if(-not ($ExistingIP.IPAddressToString -eq $FileshareIPStringList[$FileShareHostIndex]))
            {
                # File must be rewritten to update the IP
                $RewriteFile = $true
            }
            else
            {
                Write-Information "IP Address $fileshareIPString for File Share $FileShareHost is already in the route table"
            }

            # Add route to the rewrite table if it is needed later
            $AzureFileRewriteRoutes += "$($VPNRouteAddList[$FileShareHostIndex]) $VPNRouteHeader $($FileShareResolvedHostList[$FileShareHostIndex])"

            # Remove File Share from the list
            $FileShareResolvedHostList.RemoveAt($FileShareHostIndex)
            $FileshareIPStringList.RemoveAt($FileShareHostIndex)
            $VPNRouteAddList.RemoveAt($FileShareHostIndex)
        }
        else
        {
            # Force a rewrite to remove this route as it is no longer resolveable or in the list to be added
            Write-Warning "$RouteFileShare is either not resolvable or not in the list to add to the route. This will be removed"
            $RewriteFile = $true
            continue
        }
    }
    # Save Non-Azure Files Marked Routes
    else
    {
        $StandardRoutes += $Route
    }
}

$RouteTableChanged = $false
$VPNConnected = $false

# Check if the route file must be rewritten
if($RewriteFile)
{
    $RouteTableChanged = $true

    # Add the rewritten routes
    $StandardRoutes += $AzureFileRewriteRoutes

    # Rewrite the file without the old line
    $StandardRoutes | out-file $VPNRoutePath -Encoding ascii
}

# Add any routes were not already present in the list
for($index = 0; $index -lt $FileShareResolvedHostList.Count; $index++)
{
    $RouteTableChanged = $true
    Add-Content $VPNRoutePath "$($VPNRouteAddList[$index]) $VPNRouteHeader $($FileShareResolvedHostList[$index])"
}


# Check if the VPN is currently running
$rasdialQueryResult = rasdial.exe
if($rasdialQueryResult -match $VNetId)
{
    $VPNConnected = $true
}

# If it is running and a route change occured, disconnect it
if($VPNConnected -and $RouteTableChanged)
{
    $rasdialDisconnectResult = rasdial.exe $VNetId /DISCONNECT
    if($LASTEXITCODE -eq 0)
    {
        Write-Information "VPN connection $VNetId successfullly disconnected"
    }
    else
    {
        Write-Error "VPN connect $VNetId did not successfullly disconnect with error $LASTEXITCODE"
    }
}

# If VPN is not connected or the rounting table was updated, start it again
if(!$VPNConnected -or $RouteTableChanged)
{
    $rasdialConnectResult = rasdial.exe $VNetId /PHONEBOOK:"$VPNPhonebookPath"
    if($LASTEXITCODE -eq 0)
    {
        Write-Information "VPN connection $VNetId successfullly connected"

        $routeSetResult = rundll32.exe "$VPNDllRoutePath",SetRoutes /STATIC_FILE_NAME "$VPNRoutePath" /TunnelRasPhonebook "$VPNPhonebookPath" /IPHLPAPI_ACCESS_DENIED_OK /ServiceName $VNetId
        if($LASTEXITCODE -eq 0)
        {
            Write-Information "VPN connection $VNetId successfullly set routes"
        }
        else
        {
            Write-Error "VPN connection $VNetId did not successfullly set routes with error $LASTEXITCODE"
        }
    }
    else
    {
        Write-Error "VPN connect $VNetId did not successfullly connect with error $LASTEXITCODE"
    }    
}
else
{
    Write-Information "VPN connection $VNetId is already running with correct routes and does not need to be restarted"
}
