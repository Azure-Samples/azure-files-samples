using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.Specialized
using namespace System.Text

function Get-IsElevatedSession {
    <#
    .SYNOPSIS
    Get the elevation status of the PowerShell session.

    .DESCRIPTION
    This cmdlet will check to see if the PowerShell session is running as administrator, generally allowing PowerShell code 
    to check to see if it's got enough permissions to do the things it needs to do. This cmdlet is not yet defined on Linux/macOS
    sessions.
    
    .EXAMPLE
    if ((Get-IsElevatedSession)) {
        # Some code requiring elevation
    } else {
        # Some alternative code, or a nice error message.
    }

    .OUTPUTS 
    System.Boolean, indicating whether the session is elevated.
    #>

    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)

            return $isAdmin
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Assert-IsElevatedSession {
    <#
    .SYNOPSIS
    Check if the session is elevated and throw an error if it isn't.
    
    .DESCRIPTION
    This cmdlet uses the Get-IsElevatedSession cmdlet to throw a nice error message to the user if the session isn't elevated.
    
    .EXAMPLE
    Assert-IsElevatedSession
    # User sees either nothing (session is elevated), or an error message (session is not elevated).
    #>

    [CmdletBinding()]
    param()

    if (!(Get-IsElevatedSession)) {
        Write-Error `
            -Message "This cmdlet requires an elevated PowerShell session." `
            -ErrorAction Stop
    }
}

function Get-OSPlatform {
    <#
    .SYNOPSIS
    Get the OS running the current PowerShell session.

    .DESCRIPTION
    This cmdlet is a wrapper around the System.Runtime.InteropServices.RuntimeInformation .NET standard class that makes it easier to work with in PowerShell 5.1/6/7/etc. $IsWindows, etc. is defined in PS6+, however since it's not defined in PowerShell 5.1, it's not incredibly useful for writing PowerShell code meant to be executed in either language version. As older versions of .NET Framework do not support the RuntimeInformation .NET standard class, if the PSEdition is "Desktop", by default you're running on Windows, since only "Core" releases are cross-platform.

    .EXAMPLE
    if ((Get-OSPlatform) -eq "Windows") {
        # Do some Windows specific stuff
    }

    .OUTPUTS
    System.String, indicating the OS Platform name as defined by System.Runtime.InteropServices.RuntimeInformation.
    #>

    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        return "Windows"
    } else {
        $windows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)

        if ($windows) { 
            return "Windows"
        }
        
        $linux = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Linux)

        if ($linux) {
            return "Linux"
        }

        $osx = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::OSX)

        if ($osx) {
            return "OSX"
        }

        return "Unknown"
    }
}

function Assert-IsWindows {
    <#
    .SYNOPSIS
    Check if the session is being run on Windows and throw an error if it isn't.

    .DESCRIPTION
    This cmdlet uses the Get-OSPlatform cmdlet to throw a nice error message to the user if the session isn't Windows.

    .EXAMPLE
    Assert-IsWindows
    # User either sees nothing or an error message.
    #>

    [CmdletBinding()]
    param()

    if ((Get-OSPlatform) -ne "Windows") {
        throw [PlatformNotSupportedException]::new()
    }
}

function Get-IsDomainJoined {
    <#
    .SYNOPSIS
    Checks that script is being run in on computer that is domain-joined.
    
    .DESCRIPTION
    This cmdlet returns true if the cmdlet is running in a domain-joined session or false if it's not.

    .EXAMPLE
    if ((Get-IsDomainJoined)) {
        # Do something if computer is domain joined.
    } else {
        # Do something else if the computer is not domain joined.
    }

    .OUTPUTS
    System.Boolean, indicating whether or not the computer is domain joined.
    #>

    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $computer = Get-CimInstance -ClassName "win32_computersystem"
            if ($computer.PartOfDomain) {
                Write-Verbose -Message "Session is running in a domain-joined environment."
            } else {
                Write-Verbose -Message "Session is not running in a domain-joined environment."
            }

            return $computer.PartOfDomain
        }

        default {
            throw [PlatformNotSupportedException]::new()
        }
    }
}

function Assert-IsDomainJoined {
    <#
    .SYNOPSIS
    Check if the session is being run on a domain joined machine and throw an error if it isn't.

    .DESCRIPTION 
    This cmdlet uses the Get-IsDomainJoined cmdlet to throw a nice error message to the user if the session isn't domain joined.

    .EXAMPLE
    Assert-IsDomainJoined
    #>

    [CmdletBinding()]
    param()

    if (!(Get-IsDomainJoined)) {
        Write-Error `
                -Message "The cmdlet, script, or module must be run in a domain-joined environment." `
                -ErrorAction Stop
    }
}

function Get-OSVersion {
    <#
    .SYNOPSIS
    Get the version number of the OS.

    .DESCRIPTION
    This cmdlet provides the OS's internal version number, for example 10.0.18363.0 for Windows 10, version 1909 (the public release). This cmdlet is not yet defined on Linux/macOS sessions.

    .EXAMPLE
    if ((Get-OSVersion) -ge [System.Version]::new(10,0,0,0)) {
        # Do some Windows 10 specific stuff
    }

    .OUTPUTS
    System.Version, indicating the OS's internal version number.
    #>

    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            return [System.Environment]::OSVersion.Version
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}

function Get-WindowsInstallationType {
    <#
    .SYNOPSIS
    Get the Windows installation type (ex. Client, Server, ServerCore, etc.).

    .DESCRIPTION
    This cmdlet provides the installation type of the Windows OS, primarily to allow for cmdlet behavior changes depending on whether the cmdlet is being run on a Windows client ("Client") or a Windows Server ("Server", "ServerCore"). This cmdlet is (obviously) only available for Windows PowerShell sessions and will return a PlatformNotSupportedException for non-Windows sessions.

    .EXAMPLE
    switch ((Get-WindowsInstallationType)) {
        "Client" {
            # Do some stuff for Windows client.
        }

        { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
            # Do some stuff for Windows Server.
        }
    }

    .OUTPUTS
    System.String, indicating the Windows installation type.
    #>

    [CmdletBinding()]
    param()

    Assert-IsWindows

    $installType = Get-ItemProperty `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" `
            -Name InstallationType | `
        Select-Object -ExpandProperty InstallationType
    
    return $installType
}

# This PowerShell enumeration provides the various types of OS features. Currently, only Windows features
# are supported.
enum OSFeatureKind {
    WindowsServerFeature
    WindowsClientCapability
    WindowsClientOptionalFeature
}

# This PowerShell class provides a wrapper around the OS's internal feature mechanism. Currently, this class
# is only being used for Windows features, adding support for non-Windows features may require additional 
# properties/methods. Ultimately, this is useful since even within Windows, there are (at least) 3 different
# ways of representing features, and this is extremely painful to work with in scripts/modules.
class OSFeature {
    # A human friendly name of the feature. Some of the Windows features do not have human friendly names.
    [string]$Name

    # The internal OS name for the feature. This is what the operating system calls the feature if you use
    # the native cmdlets/commands to access it.
    [string]$InternalOSName 

    # The version of the feature. Depending on the OS feature kind, this may or may not be an issue.
    [string]$Version 

    # Whether or not the feature is installed.
    [bool]$Installed

    # The kind of feature being represented. 
    [OSFeatureKind]$FeatureKind

    # A default constructor to make this object.
    OSFeature(
        [string]$name,
        [string]$internalOSName,
        [string]$version,
        [bool]$installed,
        [OSFeatureKind]$featureKind
    ) {
        $this.Name = $name
        $this.InternalOSName = $internalOSName
        $this.Version = $version
        $this.Installed = $installed
        $this.FeatureKind = $featureKind
    }
}

function Get-OSFeature {
    <#
    .SYNOPSIS
    Get the list of available/installed features for your OS.

    .DESCRIPTION
    Get the list of available/installed features for your OS. Currently this cmdlet only works for Windows OSes, but works for both Windows client and Windows Server, which among them provide three different ways of enabling/disabling features (if there are more than three, this cmdlet doesn't suppor them yet).

    .EXAMPLE
    # Check to see if the Windows 10 client RSAT AD PowerShell module is installed. 
    if ((Get-OSPlatform) -eq "Windows" -and (Get-WindowsInstallationType) -eq "Client") {
        $rsatADFeature = Get-OSFeature | `
            Where-Object { $_.Name -eq "Rsat.ActiveDirectory.DS-LDS.Tools" }

        if ($null -eq $rsatADFeature) {
            # Feature is not installed.
        } else {
            # Feature is installed
        }
    }

    .OUTPUTS
    OSFeature (defined in this PowerShell module), representing a feature available/installed in your OS.
    #>

    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $winVer = Get-OSVersion

            switch((Get-WindowsInstallationType)) {
                "Client" {
                    # Windows client only allows the underlying cmdlets to run if the session
                    # is elevated, therefore this check is added.
                    Assert-IsElevatedSession

                    # WindowsCapabilities are only available on Windows 10.
                    if ($winVer -ge [Version]::new(10,0,0,0)) {
                        # Get-WindowsCapability appends additional fields to the actual name of the feature, ex.
                        # Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0. This code strips that out to hopefully get
                        # to something easier to use. This behavior may be changed in the future. Features exposed
                        # through Get-WindowsCapability appear to be dynamic, exposed through the internet, although
                        # it's unclear how frequently they're updated, or if the version number is guaranteed to change
                        # if they are.
                        $features = Get-WindowsCapability -Online | `
                            Select-Object `
                                @{ Name= "InternalName"; Expression = { $_.Name } },
                                @{ Name = "Name"; Expression = { $_.Name.Split("~")[0] } },
                                @{ Name = "Field1"; Expression = { $_.Name.Split("~")[1] } }, 
                                @{ Name = "Field2"; Expression = { $_.Name.Split("~")[2] } },
                                @{ Name = "Language"; Expression = { $_.Name.Split("~")[3] } },
                                @{ Name = "Version"; Expression = { $_.Name.Split("~")[4] } },
                                @{ Name = "Installed"; Expression = { $_.State -eq "Installed" } } | `
                            ForEach-Object {
                                if (![string]::IsNullOrEmpty($_.Language)) {
                                    $Name = ($_.Name + "-" + $_.Language)
                                } else {
                                    $Name = $_.Name
                                }

                                [OSFeature]::new(
                                    $Name, 
                                    $_.InternalName, 
                                    $_.Version, 
                                    $_.Installed, 
                                    [OSFeatureKind]::WindowsClientCapability)
                            }
                    }

                    # Features exposed via Get-WindowsOptionalFeature aren't versioned independently of the OS. 
                    # Updates may occur to these features, but happen inside of the normal OS process. 
                    $features += Get-WindowsOptionalFeature -Online | 
                        Select-Object `
                            @{ Name = "InternalName"; Expression = { $_.FeatureName } }, 
                            @{ Name = "Name"; Expression = { $_.FeatureName } }, 
                            @{ Name = "Installed"; Expression = { $_.State -eq "Enabled" } } | `
                        ForEach-Object {
                            [OSFeature]::new(
                                $_.Name, 
                                $_.InternalName, 
                                $winVer, 
                                $_.Installed, 
                                [OSFeatureKind]::WindowsClientOptionalFeature)
                        }
                }

                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    # Server is comparatively simpler than Windows client: Get-WindowsFeature doesn't require
                    # an elevated session and features that aren't split between these two different mechanisms.
                    # Most or all of the features should be available in most places, and of course Windows Server has
                    # unique features (Server Roles). 
                    $features = Get-WindowsFeature | `
                        Select-Object Name, Installed | `
                        ForEach-Object {
                            [OSFeature]::new(
                                $_.Name, 
                                $_.Name, 
                                $winVer, 
                                $_.Installed, 
                                [OSFeatureKind]::WindowsServerFeature)
                        }
                }
            }
        }

        "Linux" {
            throw [System.NotImplementedException]::new()
        }

        "OSX" {
            throw [System.NotImplementedException]::new()
        }

        default {
            throw [System.NotImplementedException]::new()
        }
    }

    return $features
}

function Install-OSFeature {
    <#
    .SYNOPSIS
    Install a requested operating system feature.

    .DESCRIPTION
    This cmdlet will use the underlying OS-specific feature installation methods to install the requested feature(s). This is currently Windows only.

    .PARAMETER OSFeature
    The feature(s) to be installed.

    .EXAMPLE 
    # Install the RSAT AD PowerShell module. 
    if ((Get-OSPlatform) -eq "Windows" -and (Get-WindowsInstallationType) -eq "Client") {
        $rsatADFeature = Get-OSFeature | `
            Where-Object { $_.Name -eq "Rsat.ActiveDirectory.DS-LDS.Tools" } | `
            Install-OSFeature
    }
    #>

    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ParameterSetName="OSFeature", ValueFromPipeline=$true)]
        [OSFeature[]]$OSFeature
    )

    process {
        switch ((Get-OSPlatform)) {
            "Windows" {
                Assert-IsElevatedSession
                $winVer = Get-OSVersion

                switch((Get-WindowsInstallationType)) {
                    "Client" {
                        if ($winVer -ge [version]::new(10,0,0,0)) {
                            $OSFeature | `
                                Where-Object { !$_.Installed } | `
                                Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsClientCapability } | `
                                Select-Object @{ Name = "Name"; Expression = { $_.InternalOSName } } | `
                                Add-WindowsCapability -Online | `
                                Out-Null
                        } else {
                            $foundCapabilities = $OSFeature | `
                                Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsClientCapability }
                            
                            if ($null -ne $foundCapabilities) {
                                Write-Error `
                                    -Message "Windows capabilities are not supported on Windows versions prior to Windows 10." `
                                    -ErrorAction Stop
                            }
                        }

                        $optionalFeatureNames = $OSFeature | `
                            Where-Object { !$_.Installed } | `
                            Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsClientOptionalFeature } | `
                            Select-Object @{ Name = "FeatureName"; Expression = { $_.InternalOSName } } | `
                            Enable-WindowsOptionalFeature -Online | `
                            Out-Null
                    }
            
                    { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                        $OSFeature | `
                            Where-Object { !$_.Installed } | `
                            Where-Object { $_.FeatureKind -eq [OSFeatureKind]::WindowsServerFeature } | `
                            Select-Object -ExpandProperty InternalOSName | `
                            Install-WindowsFeature | `
                            Out-Null
                    }
            
                    default {
                        Write-Error -Message "Unknown Windows installation type $_" -ErrorAction Stop
                    }
                }
            }
    
            "Linux" {
                throw [System.PlatformNotSupportedException]::new()
            }
    
            "OSX" {
                throw [System.PlatformNotSupportedException]::new()
            }
    
            default {
                throw [System.PlatformNotSupportedException]::new()
            }
        }
    }
}

function Request-OSFeature {
    <#
    .SYNOPSIS
    Request the features to be installed that are required for a cmdlet/script.

    .DESCRIPTION
    This cmdlet is a wrapper around the Install-OSFeature cmdlet, primarily to be used in cmdlets/scripts to ensure the required OS feature prerequisites are installed before the rest of the cmdlet executes. The required features, independent of the actual OS running, can be described, and this cmdlet figures out the rest.

    .PARAMETER WindowsClientCapability
    The names of features which are Windows client capabilities.

    .PARAMETER WindowsClientOptionalFeature
    The names of features which are Windows client optional features.

    .PARAMETER WindowsServerFeature
    The names of features which are Windows Server features.

    .EXAMPLE
    Request-OSFeature `
            -WindowsClientCapability "Rsat.ActiveDirectory.DS-LDS.Tools" `
            -WindowsServerFeature "RSAT-AD-PowerShell"
    #>

    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$WindowsClientCapability,

        [Parameter(Mandatory=$false)]
        [string[]]$WindowsClientOptionalFeature,

        [Parameter(Mandatory=$false)]
        [string[]]$WindowsServerFeature
    )

    $features = Get-OSFeature
    $foundFeatures = @()
    $notFoundFeatures = @()

    switch((Get-OSPlatform)) {
        "Windows" {
            switch((Get-WindowsInstallationType)) {
                "Client" {
                    $foundFeatures += $features | `
                        Where-Object { $_.Name -in $WindowsClientCapability -or $_.Name -in $WindowsClientOptionalFeature } 

                    if ($PSBoundParameters.ContainsKey("WindowsClientCapability")) { 
                        $notFoundFeatures += $WindowsClientCapability | `
                            Where-Object { $_ -notin ($foundFeatures | Select-Object -ExpandProperty Name) }
                    }

                    if ($PSBoundParameters.ContainsKey("WindowsClientOptionalFeature")) {   
                        $notFoundFeatures += $WindowsClientOptionalFeature | `
                            Where-Object { $_ -notin ($foundFeatures | Select-Object -ExpandProperty Name) }
                    }
                }

                { ($_ -eq "Server") -or ($_ -eq "Server Core") } {
                    $foundFeatures += $features | `
                        Where-Object { $_.Name -in $WindowsServerFeature }
                    
                    $notFoundFeatures += $WindowsServerFeature | `
                        Where-Object { $_ -notin ($foundFeatures | Select-Object -ExpandProperty Name) }
                }
            }
        }

        "Linux" {
            throw [System.NotImplementedException]::new()
        }

        "OSX" {
            throw [System.NotImplementedException]::new()
        }

        default {
            throw [System.NotImplementedException]::new()
        }
    }

    Install-OSFeature -OSFeature $foundFeatures

    if ($null -ne $notFoundFeatures -and $notFoundFeatures.Length -gt 0) {
        $notFoundBuilder = [StringBuilder]::new()
        $notFoundBuilder.Append("The following features could not be found: ") | Out-Null
        for($i=0; $i -lt $notFoundFeatures.Length; $i++) {
            if ($i -gt 0) {
                $notFoundBuilder.Append(", ") | Out-Null
            }

            $notFoundBuilder.Append($notFoundFeatures[$i]) | Out-Null
        }

        Write-Error -Message $notFoundBuilder.ToString() -ErrorAction Stop
    }
}

function Request-ADFeature {
    <#
    .SYNOPSIS
    Ensure the ActiveDirectory PowerShell module is installed prior to running the rest of the caller cmdlet.

    .DESCRIPTION
    This cmdlet is helper around Request-OSFeature specifically meant for the RSAT AD PowerShell module. It uses the optimization of checking if the ActiveDirectory module is available before using the Request-OSFeature cmdlet, since this is quite a bit faster (and does not require session elevation on Windows client) before using the Request-OSFeature cmdlet. This cmdlet is not exported.
    
    .EXAMPLE
    Request-ADFeature
    #>

    [CmdletBinding()]
    param()

    Assert-IsWindows

    $adModule = Get-Module -Name ActiveDirectory -ListAvailable
    if ($null -eq $adModule) {
        # OSVersion 10.0.18362 is Windows 10, version 1903. All releases below, such as 17763.x, where x is some 
        # OS build revision number, require manual installation of the RSAT package as indicated in the error message.
        if ((Get-WindowsInstallationType) -eq "Client" -and (Get-OSVersion) -lt [Version]::new(10, 0, 18362, 0)) {
            Write-Error `
                    -Message "This PowerShell module requires the ActiveDirectory RSAT module. On versions of Windows 10 prior to 1809, RSAT can be downloaded via https://www.microsoft.com/download/details.aspx?id=45520." `
                    -ErrorAction Stop
        }

        Request-OSFeature `
            -WindowsClientCapability "Rsat.ActiveDirectory.DS-LDS.Tools" `
            -WindowsServerFeature "RSAT-AD-PowerShell"
    }

    Import-Module -Name ActiveDirectory
}

function Validate-StorageAccount {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    [CmdletBinding()]
    param (
         [Parameter(Mandatory=$true, Position=0)]
         [string]$ResourceGroupName,
         [Parameter(Mandatory=$true, Position=1)]
         [string]$Name
    )

    process
    {
        # Verify the resource group exists.
        try
        {
            $ResourceGroupObject = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        }
        catch 
        {
            throw
        }

        if ($null -eq $ResourceGroupObject)
        {
            throw "Resource group not found: '$ResourceGroup'"
        }

        # Verify the storage account exists.
        Write-Verbose "Getting storage account $Name in ResourceGroup $ResourceGroupName"
        $StorageAccountObject = Get-AzStorageAccount -ResourceGroup $ResourceGroupName -Name $Name

        if ($null -eq $StorageAccountObject)
        {
            throw "Storage account not found: '$ResourceGroupName'"
        }

        Write-Verbose "Storage Account: $Name exists in Resource Group: $ResourceGroupName"

        return $StorageAccountObject
    }
}

function Ensure-KerbKeyExists {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
        Ensures the storage account has kerb keys created.
    
    .DESCRIPTION
        Ensures the storage account has kerb keys created.  These kerb keys are used for the passwords of the identities
        created for the storage account in Active Directory.
    
        Notably, this command:
        - Queries the storage account's keys to see if there are any kerb keys.
        - Generates kerb keys if they do not yet exist.

    .EXAMPLE
        PS C:\> Ensure-KerbKeyExists -ResourceGroupName "resourceGroup" -StorageAccountName "storageAccountName"
    
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Resource group name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Storage account name")]
        [string]$StorageAccountName
    )

    process {
        Write-Verbose "Ensure-KerbKeyExists - Checking for kerberos keys for account:$storageAccountName in resource group:$ResourceGroupName"

        try {
            $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
                 -ListKerbKey

            $kerb1Key = $keys | Where-Object { $_.KeyName -eq "kerb1" }
            $kerb2Key = $keys | Where-Object { $_.KeyName -eq "kerb2" }
        }
        catch {
            Write-Verbose "Caught exception: $($_.Exception.Message)"
        }

        if ($kerb1Key -eq $null) {
            #
            # The storage account doesn't have kerb keys yet.  Generate them now.
            #

            $keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb1 -ErrorAction Stop

            $kerb1Key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
                 -ListKerbKey | Where-Object { $_.KeyName -eq "kerb1" }
        
            Write-Verbose "    Key: $($kerb1Key.KeyName) generated for StorageAccount: $StorageAccountName"
        } else {
            Write-Verbose "    Key: $($kerb1Key.KeyName) exists in Storage Account: $StorageAccountName"
        }

        if ($kerb2Key -eq $null) {
            #
            # The storage account doesn't have kerb keys yet.  Generate them now.
            #

            $keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb2 -ErrorAction Stop

            $kerb2Key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
                 -ListKerbKey | Where-Object { $_.KeyName -eq "kerb2" }
        
            Write-Verbose "    Key: $($kerb2Key.KeyName) generated for StorageAccount: $StorageAccountName"
        } else {
            Write-Verbose "    Key: $($kerb2Key.KeyName) exists in Storage Account: $StorageAccountName"
        }
    }
}

function Get-ServicePrincipalName {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
        Gets the service principal name for the storage account's identity in Active Directory.
    
    .DESCRIPTION
        Gets the service principal name for the storage account's identity in Active Directory.

        Notably, this command:
            - Queries the storage account's file endpoint URL (i.e. "https://<storageAccount>.file.core.windows.net/")
            - Transforms that URL string into a SMB server service principal name 
                (i.e. "cifs\<storageaccount>.file.core.windows.net")

    .EXAMPLE
        PS C:\> Get-ServicePrincipalName -storageAccountName "storageAccount" -resourceGroupName "resourceGroup"
        cifs\storageAccount.file.core.windows.net
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$storageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$resourceGroupName
    )

    $storageAccountObject = Get-AzStorageAccount -ResourceGroup $resourceGroupName -Name $storageAccountName
    $servicePrincipalName = $storageAccountObject.PrimaryEndpoints.File -replace 'https://','cifs/'
    $servicePrincipalName = $servicePrincipalName.Substring(0, $servicePrincipalName.Length - 1);

    Write-Verbose "Setting service principal name of $servicePrincipalName"
    return $servicePrincipalName;
}

function New-ADAccountForStorageAccount {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
        Creates the identity for the storage account in Active Directory
    
    .DESCRIPTION
        Creates the identity for the storage account in Active Directory

        Notably, this command:
            - Queries the storage account to get the "kerb1" key.
            - Creates a user identity in Active Directory using "kerb1" key as the identity's password.
            - Sets the spn value of the new identity to be "cifs\<storageaccountname>.file.core.windows.net


    .EXAMPLE
        PS C:\> New-ADAccountForStorageAccount -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName, 

        [Parameter(Mandatory=$true, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$false, Position=2)]
        [string]$Domain,

        [Parameter(Mandatory=$false, Position=3)]
        [string]$OrganizationalUnit,

        [Parameter(Mandatory=$false, Position=4)]
        [ValidateSet("ServiceLogonAccount", "ComputerAccount")]
        [string]$ObjectType = "ServiceLogonAccount"
    )

    Assert-IsWindows
    Assert-IsDomainJoined
    Request-ADFeature

    Write-Verbose -Message "ObjectType: $ObjectType"

    if ([System.String]::IsNullOrEmpty($Domain)) {
        $domainInfo = Get-ADDomain

        $Domain = $domainInfo.DnsRoot
        $path = $domainInfo.DistinguishedName
    } else {
        try {
            $path = ((Get-ADDomain -Server $Domain).DistinguishedName)
        } catch {
            throw
        }
    }

    if (![System.String]::IsNullOrEmpty($OrganizationalUnit)) {
        $ou = Get-ADOrganizationalUnit -Filter { Name -eq $OrganizationalUnit } -Server $Domain

        #
        # Check to see if the OU exists before proceeding.
        #

        if ($null -eq $ou)
        {
            Write-Error `
                -Message "Could not find an organizational unit with name '$OrganizationalUnit' in the $Domain domain" `
                -ErrorAction Stop
        }

        $path = $ou.DistinguishedName
    }

    Write-Verbose "New-ADAccountForStorageAccount: Creating a AD account in domain:$Domain to represent the storage account:$StorageAccountName"

    #
    # Get the kerb key and convert it to a secure string password.
    #

    $kerb1Key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey `
        -ErrorAction Stop | Where-Object { $_.KeyName -eq "kerb1" };

    $fileServiceAccountPwdSecureString = ConvertTo-SecureString -String $kerb1Key.Value -AsPlainText -Force

    #
    # Create the identity in Active Directory.
    #

    $spnValue = Get-ServicePrincipalName -storageAccountName $StorageAccountName -resourceGroupName $ResourceGroupName -ErrorAction Stop

    try
    {
        switch ($ObjectType) {
            "ServiceLogonAccount" {
                Write-Verbose -Message "`$ServiceAccountName is $StorageAccountName"

                New-ADUser `
                    -SamAccountName $StorageAccountName `
                    -Path $path `
                    -Name $StorageAccountName `
                    -AccountPassword $fileServiceAccountPwdSecureString `
                    -AllowReversiblePasswordEncryption $false `
                    -PasswordNeverExpires $true `
                    -Description "Service logon account for Azure storage account $StorageAccountName." `
                    -ServicePrincipalNames $spnValue `
                    -Server $Domain `
                    -Enabled $true `
                    -TrustedForDelegation $true `
                    -ErrorAction Stop
                

                #
                # Set the service principal name for the identity to be "cifs\<storageAccountName>.file.core.windows.net"
                #
                # Set-ADUser -Identity $StorageAccountName -ServicePrincipalNames @{Add=$spnValue} -ErrorAction Stop
            }

            "ComputerAccount" {
                New-ADComputer `
                    -SAMAccountName $StorageAccountName `
                    -Path $path `
                    -Name $StorageAccountName `
                    -AccountPassword $fileServiceAccountPwdSecureString `
                    -AllowReversiblePasswordEncryption $false `
                    -Description "Computer account object for Azure storage account $StorageAccountName." `
                    -ServicePrincipalNames $spnValue `
                    -Server $Domain `
                    -Enabled $true `
                    -ErrorAction Stop
            }
        }
    }
    catch
    {
        #
        # Give better error message when AD exception is thrown for invalid SAMAccountName length.
        #

        if ($_.Exception.GetType().Name -eq "ADException" -and $StorageAccountName.Length -gt 20)
        {
            Write-Error -Message "
    Failed to create an Active Directory object with the name $StorageAccountName. 
    The naming conventions are different for an Azure storage account and an Active Directory SAMAccountName.
    The maximum number of characters in a SAMAccountName is 20.  Due to this limitation, storage account names
    must be less than 20 characters to be domain-joined."
        }

        throw
    }    

    Write-Verbose "New-ADAccountForStorageAccount: Complete"
}

function Get-AzStorageAccountADObject {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
    Get the AD object for a given storage account.

    .DESCRIPTION
    This cmdlet will lookup the AD object for a domain joined storage account. It will return the
    object from the ActiveDirectory module representing the type of AD object that was created,
    either a service logon account (user class) or a computer account. 

    .PARAMETER ResourceGroupName
    The name of the resource group containing the storage account. If you specify the StorageAccount 
    parameter you do not need to specify ResourceGroupName. 

    .PARAMETER StorageAccountName
    The name of the storage account that's already been domain joined to your DC. This cmdlet will return 
    nothing if the storage account has not been domain joined. If you specify StorageAccount, you do not need
    to specify StorageAccountName. 

    .PARAMETER StorageAccount
    A storage account object that has already been fetched using Get-AzStorageAccount. This cmdlet will 
    return nothing if the storage account has not been domain joined. If you specify ResourceGroupName and 
    StorageAccountName, you do not need to specify StorageAccount.

    .PARAMETER ADObjectName
    This parameter will look up a given object name in AD and cast it to the correct object type, either 
    class user (service logon account) or class computer. This parameter is primarily meant for internal use and 
    may be removed in a future release of the module.

    .PARAMETER Domain
    In combination with ADObjectName, the domain to look up the object in. This parameter is primarily 
    meant for internal use and may be removed in a future release of the module.

    .OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser or Microsoft.ActiveDirectory.Management.ADComputer,
    depending on the type of object the storage account was domain joined as.

    .EXAMPLE
    PS> Get-AzStorageAccountADObject -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount"

    .EXAMPLE
    PS> $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount"
    PS> Get-AzStorageAccountADObject -StorageAccount $StorageAccount

    .EXAMPLE
    PS> Get-AzStorageAccount -ResourceGroupName "myResourceGroup" | Get-AzStorageAccountADObject 

    In this example, note that a specific storage account has not been specified to 
    Get-AzStorageAccount. This means Get-AzStorageAccount will pipe every storage account 
    in the resource group myResourceGroup to Get-AzStorageAccountADObject.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [string]$StorageAccountName,

        [Parameter(
            Mandatory=$true, 
            Position=0, 
            ParameterSetName="StorageAccount", 
            ValueFromPipeline=$true)]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount,

        [Parameter(Mandatory=$true, Position=0, ParameterSetName="ADObjectName")]
        [string]$ADObjectName,

        [Parameter(Mandatory=$false, Position=1, ParameterSetName="ADObjectName")]
        [string]$Domain
    )

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature

        if ($PSCmdlet.ParameterSetName -eq "ADObjectName") {
            if ([System.String]::IsNullOrEmpty($Domain)) {
                $domainInfo = Get-Domain
                $Domain = $domainInfo.DnsRoot
            }
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "StorageAccountName" -or 
            $PSCmdlet.ParameterSetName -eq "StorageAccount") {

            if ($PSCmdlet.ParameterSetName -eq "StorageAccountName") {
                $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
            }

            if ($null -eq $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties) {
                return
            }

            $sid = $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.AzureStorageSid
            $Domain = $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainName

            Write-Verbose `
                -Message ("Object for storage account " + $StorageAccount.StorageAccountName + " has SID=$sid in Domain $Domain")

            $obj = Get-ADObject `
                -Server $Domain `
                -Filter { objectSID -eq $sid } `
                -ErrorAction Stop
        } else {
            $obj = Get-ADObject `
                -Server $Domain `
                -Filter { Name -eq $ADObjectName } `
                -ErrorAction Stop
        }

        if ($null -eq $obj) {
            Write-Error `
                -Message "AD object not found in $Domain" `
                -ErrorAction Stop
        }

        Write-Verbose -Message ("Found AD object: " + $obj.DistinguishedName + " of class " + $obj.ObjectClass + ".")

        switch ($obj.ObjectClass) {
            "computer" {
                $computer = Get-ADComputer `
                    -Identity $obj.DistinguishedName `
                    -Server $Domain `
                    -Properties "ServicePrincipalNames" `
                    -ErrorAction Stop
                
                return $computer
            }

            "user" {
                $user = Get-ADUser `
                    -Identity $obj.DistinguishedName `
                    -Server $Domain `
                    -Properties "ServicePrincipalNames" `
                    -ErrorAction Stop
                
                return $user
            }

            default {
                Write-Error `
                    -Message ("AD object $StorageAccountName is of unsupported object class " + $obj.ObjectClass + ".") `
                    -ErrorAction Stop
            }
        }
    }
}

function Get-AzStorageKerberosTicketStatus {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
    Gets an array of Kerberos tickets for Azure storage accounts with status information.
    
    .DESCRIPTION
    This cmdlet will query the client computer for Kerberos service tickets to Azure storage accounts.
    It will return an array of these objects, each object having a property 'Azure Files Health Status'
    which tells the health of the ticket.  It will error when there are no ticketsfound or if there are 
    unhealthy tickets found.

    .OUTPUTS
    Object[] of PSCustomObject containing klist ticket output.

    .EXAMPLE
    PS> Get-AzStorageKerberosTicketStatus
    #>

    [CmdletBinding()]
    param()

    begin {
        Assert-IsWindows
    }

    process 
    {
        $TicketsArray = klist.exe tickets
        $TicketsObject = @()
        $Counter = 0;
        $HealthyTickets = 0;
        $UnhealthyTickets = 0;

        #
        # Iterate through all the Kerberos tickets on the client, and find the service tickets corresponding to Azure
        # storage accounts.
        #

        foreach ($line in $TicketsArray)
        {
            if ($line -match "^#\d")
            {
                $Ticket = New-Object PSObject
                $Line1 = $Line.Split('>')[1]

                $Client = $Line1 ;	$Client = $Client.Replace('Client:','') ; $Client = $Client.Substring(2)
                $Server = $TicketsArray[$Counter+1]; $Server = $Server.Replace('Server:','') ;$Server = $Server.substring(2)
                $KerbTicketEType = $TicketsArray[$Counter+2];$KerbTicketEType = $KerbTicketEType.Replace('KerbTicket Encryption Type:','');$KerbTicketEType = $KerbTicketEType.substring(2)
                $TickFlags = $TicketsArray[$Counter+3];$TickFlags = $TickFlags.Replace('Ticket Flags','');$TickFlags = $TickFlags.substring(2)
                $StartTime =  $TicketsArray[$Counter+4];$StartTime = $StartTime.Replace('Start Time:','');$StartTime = $StartTime.substring(2)
                $EndTime = $TicketsArray[$Counter+5];$EndTime = $EndTime.Replace('End Time:','');$EndTime = $EndTime.substring(4)
                $RenewTime = $TicketsArray[$Counter+6];$RenewTime = $RenewTime.Replace('Renew Time:','');$RenewTime = $RenewTime.substring(2)
                $SessionKey = $TicketsArray[$Counter+7];$SessionKey = $SessionKey.Replace('Session Key Type:','');$SessionKey = $SessionKey.substring(2)

                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Client" -Value $Client
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Server" -Value $Server
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "KerbTicket Encryption Type" -Value $KerbTicketEType
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Ticket Flags" -Value $TickFlags
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Start Time" -Value $StartTime
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "End Time" -Value $EndTime
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Renew Time" -Value $RenewTime
                Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Session Key Type" -Value $SessionKey
                
                if ($Server -match "cifs" -and $Server -match "file.core.windows.net")
                {
                    #
                    # We found a ticket to an Azure storage account.  Check that it has valid encryption type.
                    #
                    
                    if ($KerbTicketEType -notmatch "RC4")
                    {
                        $WarningMessage = "Unhealthy - Unsupported KerbTicket Encryption Type $KerbTicketEType"
                        Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Azure Files Health Status" -Value $WarningMessage
                        $UnhealthyTickets++;
                    }
                    else
                    {
                        Add-Member -InputObject $Ticket -MemberType NoteProperty -Name "Azure Files Health Status" -Value "Healthy"
                        $HealthyTickets++;
                    }
                
                    $TicketsObject += $Ticket 
                }
            }

            $Ticket = $null
            $Counter++
        }

        Write-Verbose "Azure Files Kerberos Ticket Health Check Summary:"

        if (($HealthyTickets + $UnhealthyTickets) -eq 0)
        {
            Write-Error "$($HealthyTickets + $UnhealthyTickets) Kerberos service tickets to Azure storage accounts were detected.
        Run the following command: 
            
            'klist get cifs/<storageaccountname>.file.core.windows.net'

        to request a ticket and then rerun this status command.
        "
        }
        else 
        {
            Write-Verbose "$($HealthyTickets + $UnhealthyTickets) Kerberos service tickets to Azure storage accounts were detected."
        }
        
        if ($UnhealthyTickets -ne 0)
        {
            Write-Warning "$UnhealthyTickets unhealthy Kerberos service tickets to Azure storage accounts were detected."
        }

        $Counter = 1;
        foreach ($TicketObj in ,$TicketsObject)
        {
            Write-Verbose "Ticket #$Counter : $($TicketObj.'Azure Files Health Status')"

            if ($TicketObj.'Azure Files Health Status' -match "Unhealthy")
            {
                Write-Error "Ticket #$Counter hit error
        Server: $($TicketObj.'Server')
        Status: $($TicketObj.'Azure Files Health Status')"

            }

            $TicketObj | Format-List | Out-String|% {Write-Verbose $_}
        }

        return ,$TicketsObject
    }
}

function Set-StorageAccountDomainProperties {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
       This sets the storage account's ActiveDirectoryProperties - information needed to support the UI
       experience for getting and setting file and directory permissions.
    
    .DESCRIPTION
        Creates the identity for the storage account in Active Directory

        Notably, this command:
            - Queries the domain for the identity created for the storage account.
                - ActiveDirectoryAzureStorageSid
                    - The SID of the identity created for the storage account.
            - Queries the domain information for the required properties using Active Directory PowerShell module's 
              Get-ADDomain cmdlet
                - ActiveDirectoryDomainGuid
                    - The GUID used as an identifier of the domain
                - ActiveDirectoryDomainName
                    - The name of the domain
                - ActiveDirectoryDomainSid
                - ActiveDirectoryForestName
                - ActiveDirectoryNetBiosDomainName
            - Sets these properties on the storage account.

    .EXAMPLE
        PS C:\> Create-ServiceAccount -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$false, Position=2)]
        [string]$Domain
    )

    Assert-IsWindows
    Assert-IsDomainJoined
    Request-ADFeature

    Write-Verbose "Set-StorageAccountDomainProperties: Enabling the feature on the storage account and providing the required properties to the storage service"

    if ([System.String]::IsNullOrEmpty($Domain)) {
        $domainInformation = Get-ADDomain
        $Domain = $domainInformation.DnsRoot
    } else {
        $domainInformation = Get-ADDomain -Server $Domain
    }

    $azureStorageIdentity = Get-AzStorageAccountADObject `
        -ADObjectName $StorageAccountName `
        -Domain $Domain `
        -ErrorAction Stop
    $azureStorageSid = $azureStorageIdentity.SID.Value

    $domainGuid = $domainInformation.ObjectGUID.ToString()
    $domainName = $domainInformation.DnsRoot
    $domainSid = $domainInformation.DomainSID.Value
    $forestName = $domainInformation.Forest
    $netBiosDomainName = $domainInformation.DnsRoot

    Write-Verbose "Setting AD properties on $StorageAccountName in $ResourceGroupName : ActiveDirectoryDomainName=$domainName, `
        ActiveDirectoryNetBiosDomainName=$netBiosDomainName, ActiveDirectoryForestName=$($domainInformation.Forest) `
        ActiveDirectoryDomainGuid=$domainGuid, ActiveDirectoryDomainSid=$domainSid, `
        ActiveDirectoryAzureStorageSid=$azureStorageSid"

    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName `
         -EnableActiveDirectoryDomainServicesForFile $true -ActiveDirectoryDomainName $domainName `
         -ActiveDirectoryNetBiosDomainName $netBiosDomainName -ActiveDirectoryForestName $forestName `
         -ActiveDirectoryDomainGuid $domainGuid -ActiveDirectoryDomainSid $domainSid `
         -ActiveDirectoryAzureStorageSid $azureStorageSid

    Write-Verbose "Set-StorageAccountDomainProperties: Complete"
}

# A class for structuring the results of the Test-AzStorageAccountADObjectPasswordIsKerbKey cmdlet.
class KerbKeyMatch {
    # The resource group of the storage account that was tested.
    [string]$ResourceGroupName

    # The name of the storage account that was tested.
    [string]$StorageAccountName

    # The Kerberos key, either kerb1 or kerb2.
    [string]$KerbKeyName

    # Whether or not the key matches.
    [bool]$KeyMatches

    # A default constructor for the KerbKeyMatch class.
    KerbKeyMatch(
        [string]$resourceGroupName,
        [string]$storageAccountName,
        [string]$kerbKeyName,
        [bool]$keyMatches 
    ) {
        $this.ResourceGroupName = $resourceGroupName
        $this.StorageAccountName = $storageAccountName
        $this.KerbKeyName = $kerbKeyName
        $this.KeyMatches = $keyMatches
    }
}

function Test-AzStorageAccountADObjectPasswordIsKerbKey {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
    Check Kerberos keys kerb1 and kerb2 against the AD object for the storage account.

    .DESCRIPTION
    This cmdlet checks to see if kerb1, kerb2, or something else matches the actual password on the AD object. This cmdlet can be used to validate that authentication issues are not occurring because the password on the AD object does not match one of the Kerberos keys. It is also used by Invoke-AzStorageAccountADObjectPasswordRotation to determine which Kerberos to rotate to.

    .PARAMETER ResourceGroupName
    The resource group of the storage account to check.

    .PARAMETER StorageAccountName
    The storage account name of the storage account to check.

    .PARAMETER StorageAccount
    The storage account to check.

    .EXAMPLE
    PS> Test-AzStorageAccountADObjectPasswordIsKerbKey -ResourceGroupName "myResourceGroup" -StorageAccountName "mystorageaccount123"

    .EXAMPLE
    PS> $storageAccountsToCheck = Get-AzStorageAccount -ResourceGroup "rgWithDJStorageAccounts"
    PS> $storageAccountsToCheck | Test-AzStorageAccountADObjectPasswordIsKerbKey 

    .OUTPUTS
    KerbKeyMatch, defined in this module.
    #>

    [CmdletBinding()]
    param(
         [Parameter(Mandatory=$true, Position=0, ParameterSetName="StorageAccountName")]
         [string]$ResourceGroupName,

         [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
         [Alias('Name')]
         [string]$StorageAccountName,

         [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ParameterSetName="StorageAccount")]
         [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount
    )

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process
    {
        $getObjParams = @{}
        switch ($PSCmdlet.ParameterSetName) {
            "StorageAccountName" {
                $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey
                $getObjParams += @{ 
                    "ResourceGroupName" = $ResourceGroupName; 
                    "StorageAccountName" = $StorageAccountName 
                }
            }

            "StorageAccount" {
                $keys = $StorageAccount | Get-AzStorageAccountKey -ListKerbKey
                $ResourceGroupName = $StorageAccount.ResourceGroupName
                $StorageAccountName = $StorageAccount.StorageAccountName
                $getObjParams += @{
                    "StorageAccount" = $StorageAccount
                }
            }

            default {
                throw [ArgumentException]::new("Unrecognized parameter set $_")
            }
        }
        
        $kerbKeys = $keys | Where-Object { $_.KeyName -like "kerb*" }
        $adObj = Get-AzStorageAccountADObject @getObjParams

        $domainNameBuilder = [StringBuilder]::new() 
        $domainArray = $adObj.DistinguishedName.Split(",") | Where-Object { $_ -like "DC=*" }
        for($i=0; $i -lt $domainArray.Length; $i++) {
            if ($i -gt 0) {
                $domainNameBuilder.Append(",") | Out-Null
            }

            $domainNameBuilder.Append($domainArray[$i]) | Out-Null
        }

        $domain = Get-ADDomain -Identity $domainNameBuilder.ToString()
        $userName = $domain.Name + "\" + $adObj.Name

        $oneKeyMatches = $false
        $keyMatches = [KerbKeyMatch[]]@()
        foreach ($key in $kerbKeys) {
            if ($null -ne (New-Object Directoryservices.DirectoryEntry "", $userName, $key.Value).PsBase.Name) {
                Write-Verbose "Found that $($key.KeyName) matches password for $Name in AD."
                $oneKeyMatches = $true
                $keyMatches += [KerbKeyMatch]::new(
                    $ResourceGroupName, 
                    $StorageAccountName, 
                    $key.KeyName, 
                    $true)
            } else {
                $keyMatches += [KerbKeyMatch]::new(
                    $ResourceGroupName, 
                    $StorageAccountName, 
                    $key.KeyName, 
                    $false)
            }
        }

        if (!$oneKeyMatches) {
            Write-Warning `
                    -Message ("Password for $userName does not match kerb1 or kerb2 of storage account: $StorageAccountName." + `
                    "Please run the following command to resync the AD password with the kerb key of the storage account and " +  `
                    "retry: Update-AzStorageAccountADObjectPassword.")
        }

        return $keyMatches
    }
}

function Update-AzStorageAccountADObjectPassword {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
    Switch the password of the AD object representing the storage account to the indicated kerb key.

    .DESCRIPTION
    This cmdlet will switch the password of the AD object (either a service logon account or a computer 
    account, depending on which you selected when you domain joined the storage account to your DC), 
    to the indicated kerb key, either kerb1 or kerb2. The purpose of this action is to perform a 
    password rotation of the active kerb key being used to authenticate access to your Azure file 
    shares. This cmdlet itself will regenerate the selected kerb key as specified by (RotateToKerbKey) 
    and then reset the password of the AD object to that kerb key. This is intended to be a two-stage 
    split over several hours where both kerb keys are rotated. The default key used when the storage 
    account is domain joined is kerb1, so to do a rotation, switch to kerb2, wait several hours, and then
    switch back to kerb1 (this cmdlet regenerates the keys before switching).

    .PARAMETER RotateToKerbKey
    The kerb key of the storage account that the AD object representing the storage account in your DC 
    will be set to.

    .PARAMETER ResourceGroupName
    The name of the resource group containing the storage account. If you specify the StorageAccount 
    parameter you do not need to specify ResourceGroupName. 

    .PARAMETER StorageAccountName
    The name of the storage account that's already been domain joined to your DC. This cmdlet will fail
    if the storage account has not been domain joined. If you specify StorageAccount, you do not need
    to specify StorageAccountName. 

    .PARAMETER StorageAccount
    A storage account object that has already been fetched using Get-AzStorageAccount. This cmdlet will 
    fail if the storage account has not been domain joined. If you specify ResourceGroupName and 
    StorageAccountName, you do not need to specify StorageAccount.

    .Example
    PS> Update-AzStorageAccountADObjectPassword -RotateToKerbKey kerb2 -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount"
    
    .Example 
    PS> $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "myStorageAccount"
    PS> Update-AzStorageAccountADObjectPassword -RotateToKerbKey kerb2 -StorageAccount $storageAccount 
    
    .Example
    PS> Get-AzStorageAccount -ResourceGroupName "myResourceGroup" | Update-AzStorageAccountADObjectPassword -RotateToKerbKey
    
    In this example, note that a specific storage account has not been specified to 
    Get-AzStorageAccount. This means Get-AzStorageAccount will pipe every storage account 
    in the resource group myResourceGroup to Update-AzStorageAccountADObjectPassword.
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet("kerb1", "kerb2")]
        [string]$RotateToKerbKey,

        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=2, ParameterSetName="StorageAccountName")]
        [string]$StorageAccountName,

        [Parameter(
            Mandatory=$true, 
            Position=1, 
            ValueFromPipeline=$true, 
            ParameterSetName="StorageAccount")]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount,

        [Parameter(Mandatory=$false)]
        [switch]$SkipKeyRegeneration

        #[Parameter(Mandatory=$false)]
        #[switch]$Force
    )

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "StorageAccountName") {
            Write-Verbose -Message "Get storage account object for StorageAccountName=$StorageAccountName."
            $StorageAccount = Get-AzStorageAccount `
                -ResourceGroupName $ResourceGroupName `
                -Name $StorageAccountName `
                -ErrorAction Stop
        }

        if ($null -eq $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties) {
            Write-Error `
                -Message ("Storage account " + $StorageAccount.StorageAccountName + " has not been domain joined.") `
                -ErrorAction Stop
        }

        switch ($RotateToKerbKey) {
            "kerb1" {
                $otherKerbKeyName = "kerb2"
            }

            "kerb2" {
                $otherKerbKeyName = "kerb1"
            }
        }
        
        $adObj = Get-AzStorageAccountADObject -StorageAccount $StorageAccount

        $caption = ("Set password on AD object " + $adObj.SamAccountName + `
            " for " + $StorageAccount.StorageAccountName + " to value of $RotateToKerbKey.")
        $verboseConfirmMessage = ("This action will change the password for the indicated AD object " + `
            "from $otherKerbKeyName to $RotateToKerbKey. This is intended to be a two-stage " + `
            "process: rotate from kerb1 to kerb2 (kerb2 will be regenerated on the storage " + `
            "account before being set), wait several hours, and then rotate back to kerb1 " + `
            "(this cmdlet will likewise regenerate kerb1).")

        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            Write-Verbose -Message "Desire to rotate password confirmed."
            
            Write-Verbose -Message ("Regenerate $RotateToKerbKey on " + $StorageAccount.StorageAccountName)
            if (!$SkipKeyRegeneration.ToBool()) {
                $kerbKeys = New-AzStorageAccountKey `
                    -ResourceGroupName $StorageAccount.ResourceGroupName `
                    -Name $StorageAccount.StorageAccountName `
                    -KeyName $RotateToKerbKey `
                    -ErrorAction Stop | `
                Select-Object -ExpandProperty Keys
            } else {
                $kerbKeys = Get-AzStorageAccountKey `
                    -ResourceGroupName $StorageAccount.ResourceGroupName `
                    -Name $StorageAccount.StorageAccountName `
                    -ListKerbKey `
                    -ErrorAction Stop
            }             
        
            $kerbKey = $kerbKeys | `
                Where-Object { $_.KeyName -eq $RotateToKerbKey } | `
                Select-Object -ExpandProperty Value  
    
            $otherKerbKey = $kerbKeys | `
                Where-Object { $_.KeyName -eq $otherKerbKeyName } | `
                Select-Object -ExpandProperty Value
    
            $oldPassword = ConvertTo-SecureString -String $otherKerbKey -AsPlainText -Force
            $newPassword = ConvertTo-SecureString -String $kerbKey -AsPlainText -Force
    
            # if ($Force.ToBool()) {
                Write-Verbose -Message ("Attempt reset on " + $adObj.SamAccountName + " to $RotateToKerbKey")
                Set-ADAccountPassword `
                    -Identity $adObj `
                    -Reset `
                    -NewPassword $newPassword `
                    -ErrorAction Stop
            # } else {
            #     Write-Verbose `
            #         -Message ("Change password on " + $adObj.SamAccountName + " from $otherKerbKeyName to $RotateToKerbKey.")
            #     Set-ADAccountPassword `
            #         -Identity $adObj `
            #         -OldPassword $oldPassword `
            #         -NewPassword $newPassword `
            #         -ErrorAction Stop
            # }

            Write-Verbose -Message "Password changed successfully."
        } else {
            Write-Verbose -Message ("Password for " + $adObj.SamAccountName + " for storage account " + `
                $StorageAccount.StorageAccountName + " not changed.")
        }        
    }
}

function Invoke-AzStorageAccountADObjectPasswordRotation {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS
    Do a password rotation of kerb key used on the AD object representing the storage account.

    .DESCRIPTION
    This cmdlet wraps Update-AzStorageAccountADObjectPassword to rotate whatever the current kerb key is to the other one. It's not strictly speaking required to do a rotation, always regenerating kerb1 is ok to do is well.

    .PARAMETER ResourceGroupName
    The resource group of the storage account to be rotated.

    .PARAMETER StorageAccountName
    The name of the storage account to be rotated. 

    .PARAMETER StorageAccount
    The storage account to be rotated.

    .EXAMPLE
    PS> Invoke-AzStorageAccountADObjectPasswordRotation -ResourceGroupName "myResourceGroup" -StorageAccountName "mystorageaccount123"

    .EXAMPLE
    PS> $storageAccounts = Get-AzStorageAccount -ResourceGroupName "myResourceGroup"
    PS> $storageAccounts | Invoke-AzStorageAccountADObjectPasswordRotation
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=2, ParameterSetName="StorageAccountName")]
        [string]$StorageAccountName,

        [Parameter(
            Mandatory=$true, 
            Position=1, 
            ValueFromPipeline=$true, 
            ParameterSetName="StorageAccount")]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount
    )

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process {
        $testParams = @{}
        $updateParams = @{}
        switch ($PSCmdlet.ParameterSetName) {
            "StorageAccountName" {
                $testParams += @{ 
                    "ResourceGroupName" = $ResourceGroupName; 
                    "StorageAccountName" = $StorageAccountName 
                }

                $updateParams += @{
                    "ResourceGroupName" = $ResourceGroupName;
                    "StorageAccountName" = $StorageAccountName
                }
            }

            "StorageAccount" {
                $testParams += @{ 
                    "StorageAccount" = $StorageAccount 
                }

                $updateParams += @{
                    "StorageAccount" = $StorageAccount
                }
            }

            default {
                throw [ArgumentException]::new("Unrecognized parameter set $_")
            }
        }

        $testParams += @{ "WarningAction" = "SilentlyContinue" }

        $keyMatches = Test-AzStorageAccountADObjectPasswordIsKerbKey @testParams
        $keyMatch = $keyMatches | Where-Object { $_.KeyMatches }

        switch ($keyMatch.KerbKeyName) {
            "kerb1" {
                $updateParams += @{
                    "RotateToKerbKey" = "kerb2"
                }
                $RotateFromKerbKey = "kerb1"
                $RotateToKerbKey = "kerb2"
            }

            "kerb2" {
                $updateParams += @{
                    "RotateToKerbKey" = "kerb1"
                }
                $RotateFromKerbKey = "kerb2"
                $RotateToKerbKey = "kerb1"
            }

            $null {
                $updateParams += @{
                    "RotateToKerbKey" = "kerb1"
                }
                $RotateFromKerbKey = "none"
                $RotateToKerbKey = "kerb1"
            }

            default {
                throw [ArgumentException]::new("Unrecognized kerb key $_")
            }
        }

        $caption = "Rotate from Kerberos key $RotateFromKerbKey to $RotateToKerbKey."
        $verboseConfirmMessage = "This action will rotate the password from $RotateFromKerbKey to $RotateToKerbKey using Update-AzStorageAccountADObjectPassword." 
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            Update-AzStorageAccountADObjectPassword @updateParams
        } else {
            Write-Verbose -Message "No password rotation performed."
        }
    }
}

function Join-AzStorageAccountForAuth {
    #requires -Module @{ ModuleName = "Az.Storage"; RequiredVersion = "1.8.2" }

    <#
    .SYNOPSIS 
    Domain join a storage account to an Active Directory Domain Controller.

    .DESCRIPTION
    This cmdlet will perform the equivalent of an offline domain join on behalf of the indicated storage account.
    It will create an object in your AD domain, either a service logon account (which is really a user account) or a computer account
    account. This object will be used to perform Kerberos authentication to the Azure file shares in your storage account.

    .PARAMETER ResourceGroupName
    The name of the resource group containing the storage account you would like to domain join. If StorageAccount is specified, 
    this parameter should not specified.

    .PARAMETER StorageAccountName
    The name of the storage account you would like to domain join. If StorageAccount is specified, this parameter 
    should not be specified.

    .PARAMETER StorageAccount
    A storage account object you would like to domain join. If StorageAccountName and ResourceGroupName is specified, this 
    parameter should not specified.

    .PARAMETER Domain
    The domain you would like to join the storage account to. If you would like to join the same domain as the one you are 
    running the cmdlet from, you do not need to specify this parameter.

    .PARAMETER DomainAccountType
    The type of AD object to be used either a service logon account (user account) or a computer account. The default is to create 
    service logon account.

    .PARAMETER OrganizationalUnitName
    The organizational unit for the AD object to be added to. This parameter is optional, but many environments will require it.

    .PARAMETER ADObjectNameOverride
    By default, the AD object that is created will have a name to match the storage account. This parameter overrides that to an
    arbitrary name. This does not affect how you access your storage account.

    .EXAMPLE
    PS> Join-AzStorageAccountForAuth -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount" -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"

    .EXAMPLE 
    PS> $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "myStorageAccount"
    PS> Join-AzStorageAccountForAuth -StorageAccount $storageAccount -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"

    .EXAMPLE
    PS> Get-AzStorageAccount -ResourceGroupName "myResourceGroup" | Join-AzStorageAccountForAuth -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"

    In this example, note that a specific storage account has not been specified to 
    Get-AzStorageAccount. This means Get-AzStorageAccount will pipe every storage account 
    in the resource group myResourceGroup to Join-AzStorageAccountForAuth.
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [Alias('Name')]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ParameterSetName="StorageAccount")]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount,

        [Parameter(Mandatory=$false, Position=2)]
        [string]$Domain,

        [Parameter(Mandatory=$false, Position=3)]
        [ValidateSet("ServiceLogonAccount", "ComputerAccount")]
        [string]$DomainAccountType = "ServiceLogonAccount",

        [Parameter(Mandatory=$false, Position=4)]
        [string]$OrganizationalUnitName,

        [Parameter(Mandatory=$false, Position=5)]
        [string]$ADObjectNameOverride
    ) 

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process {
        if (![System.String]::IsNullOrEmpty($ADObjectNameOverride)) {
            Write-Error -Message "Specifying an override for a service/computer account is not currently implemented." -ErrorAction Stop
        }

        if ($PSCmdlet.ParameterSetName -eq "StorageAccount") {
            $StorageAccountName = $StorageAccount.StorageAccountName
            $ResourceGroupName = $StorageAccount.ResourceGroupName
        }

        $caption = "Domain join $StorageAccountName"
        $verboseConfirmMessage = ("This action will domain join the requested storage account to the requested domain.")
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            # Ensure the storage account exists.
            if ($PSCmdlet.ParameterSetName -eq "StorageAccountName") {
                $StorageAccount = Validate-StorageAccount `
                    -ResourceGroup $ResourceGroupName `
                    -Name $StorageAccountName `
                    -ErrorAction Stop
            }

            if ($null -ne $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties) {
                Write-Verbose "Storage account $StorageAccountName is already domain joined."
                return
            }
                
            # Ensure the storage account has a "kerb1" key.
            Ensure-KerbKeyExists -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop

            # Create the service account object for the storage account.
            New-ADAccountForStorageAccount `
                -StorageAccountName $StorageAccountName `
                -ResourceGroupName $ResourceGroupName `
                -Domain $Domain `
                -OrganizationalUnit $OrganizationalUnitName `
                -ObjectType $DomainAccountType `
                -ErrorAction Stop

            # Set domain properties on the storage account.
            Set-StorageAccountDomainProperties `
                -ResourceGroupName $ResourceGroupName `
                -StorageAccountName $StorageAccountName `
                -Domain $Domain
        }
    }
}

function Expand-AzResourceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$ResourceId
    )

    process {
        $split = $ResourceId.Split("/")
        $split = $split[1..$split.Length]
    
        $result = [OrderedDictionary]::new()
        $key = [string]$null
        $value = [string]$null

        for($i=0; $i -lt $split.Length; $i++) {
            if (!($i % 2)) {
                $key = $split[$i]
            } else {
                $value = $split[$i]
                $result.Add($key, $value)

                $key = [string]$null
                $value = [string]$null
            }
        }

        return $result
    }
}

function Compress-AzResourceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [OrderedDictionary]$ExpandedResourceId
    )   

    process {
        $sb = [StringBuilder]::new()

        foreach($entry in $ExpandedResourceId.GetEnumerator()) {
            $sb.Append(("/" + $entry.Key + "/" + $entry.Value)) | Out-Null
        }

        return $sb.ToString()
    }
}

function Request-ConnectAzureAD {
    [CmdletBinding()]
    param()

    $aadModule = Get-Module | Where-Object { $_.Name -like "AzureAD" }
    if ($null -eq $aadModule) {
        if ($PSVersionTable.PSVersion -ge [Version]::new(6,0,0,0)) {
            Import-WinModule -Name AzureAD
        } else {
            Import-Module -Name AzureAD
        }
    }

    try {
        Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
    } catch {
        $context = Get-AzContext
        Connect-AzureAD `
                -TenantId $context.Tenant.Id `
                -AccountId $context.Account.Id `
                -AzureEnvironmentName $context.Environment.Name | `
            Out-Null
    }
}

function Get-AzureADDomainInternal {
    [CmdletBinding()]
    param()

    Assert-IsWindows
    Request-ConnectAzureAD
    
    return (Get-AzureADDomain)
}

function Get-AzCurrentAzureADUser {
    [CmdletBinding()]
    param()

    $context = Get-AzContext
    $friendlyLogin = $context.Account.Id
    $friendlyLoginSplit = $friendlyLogin.Split("@")

    $domains = Get-AzureADDomainInternal
    $domainNames = $domains | Select-Object -ExpandProperty Name

    if ($friendlyLoginSplit[1] -in $domainNames) {
        return $friendlyLogin
    } else {
        $username = ($friendlyLoginSplit[0] + "_" + $friendlyLoginSplit[1] + "#EXT#")

        foreach($domain in $domains) {
            $possibleName = ($username + "@" + $domain.Name) 
            $foundUser = Get-AzADUser -UserPrincipalName $possibleName
            if ($null -ne $foundUser) {
                return $possibleName
            }
        }
    }
}

$ClassicAdministratorsSet = $false
$ClassicAdministrators = [HashSet[string]]::new()
$OperationCache = [Dictionary[string, Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleDefinition[]]]::new()
function Test-AzPermission {
    #requires -Module Az.Resources

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("ResourceId", "Id")]
        [string]$Scope,

        [Parameter(Mandatory=$true, ParameterSetName="OperationsName")]
        [string[]]$OperationName,

        [Parameter(Mandatory=$true, ParameterSetName="OperationsObj")]
        [Microsoft.Azure.Commands.Resources.Models.PSResourceProviderOperation[]]$Operation,

        [Parameter(Mandatory=$false)]
        [string]$SignInName,

        [Parameter(Mandatory=$false)]
        [switch]$RefreshCache
    )

    begin {
        # Populate the classic administrator cache
        if (!$ClassicAdministratorsSet -or $RefreshCache) {
            if (!$ClassicAdministratorsSet) {
                $ClassicAdministratorsSet = $true
            } else {
                $ClassicAdministrators.Clear()
            }

            $ResourceIdComponents = $Scope | Expand-AzResourceId
            $subscription = $ResourceIdComponents.subscriptions
            $roleAssignments = Get-AzRoleAssignment `
                    -Scope "/subscriptions/$subscription" `
                    -IncludeClassicAdministrators | `
                Where-Object { $_.Scope -eq "/subscriptions/$subscription" }
            
            $_classicAdministrators = $roleAssignments | `
                Where-Object { 
                    $split = $_.RoleDefinitionName.Split(";"); 
                    "CoAdministrator" -in $split -or "ServiceAdministrator" -in $split
                }
            
            foreach ($admin in $_classicAdministrators) {
                $ClassicAdministrators.Add($admin.SignInName) | Out-Null
            }
        }
    }

    process {
        # Normalize operations to $Operation
        if ($PSCmdlet.ParameterSetName -eq "OperationsName") {
            $Operation = $OperationName | `
                Get-AzProviderOperation
        }

        # If a specific user isn't given, use the current PowerShell logged in user.
        # This is expected to be the normal case.
        if (!$PSBoundParameters.ContainsKey("SignInName")) {
            $SignInName = Get-AzCurrentAzureADUser
        }

        # Build lookup dictionary of which operations the user has. Start with having none.
        $userHasOperation = [Dictionary[string, bool]]::new()
        foreach($op in $Operation) {
            $userHasOperation.Add($op.Operation, $false)
        }        

        # Get the classic administrator sign in name. If the user is using an identity based on 
        # the name (i.e. jdoe@contoso.com), these are the same. If the user is using an identity 
        # external, ARM will contain #EXT# and classic won't.
        $ClassicSignInName = $SignInName
        if ($SignInName -like "*#EXT#*") {
            $SignInSplit = $SignInName.Split("@")
            $ClassicSignInName = $SignInSplit[0].Replace("#EXT#", "").Replace("_", "@")
        }

        if ($ClassicAdministrators.Contains($ClassicSignInName)) {
            foreach($op in $Operation) {
                $userHasOperation[$op.Operation] = $true
            }

            return $userHasOperation
        }

        $roleAssignments = Get-AzRoleAssignment -Scope $Scope -SignInName $SignInName

        if ($RefreshCache) {
            $OperationCache.Clear()
        }

        foreach($roleAssignment in $roleAssignments) {
            $operationsInRole = [string[]]$null
            if (!$OperationCache.TryGetValue($roleAssignment.RoleDefinitionId, [ref]$operationsInRole)) {
                $operationsInRole = Get-AzRoleDefinition -Id $roleAssignment.RoleDefinitionId
                $OperationCache.Add($roleAssignment.RoleDefinitionId, $operationsInRole)
            }

            foreach($op in $Operation) {
                $matches = $false

                if (!$op.IsDataAction) {
                    foreach($action in $operationsInRole.Actions) {
                        if ($op.Operation -like $action) {
                            $matches = $true
                            break
                        }
                    }

                    if ($matches) {
                        foreach($notAction in $operationsInRole.NotActions) {
                            if ($op.Operation -like $notAction) {
                                $matches = $false
                                break
                            }
                        }
                    }
                } else {
                    foreach($dataAction in $operationsInRole.DataActions) {
                        if ($op.Operation -like $dataAction) {
                            $matches = $true
                            break
                        }
                    }

                    if ($matches) {
                        foreach($notDataAction in $operationsInRole.NotDataActions) {
                            if ($op.Operation -like $notDataAction) {
                                $matches = $false
                                break
                            }
                        }
                    }
                }

                $userHasOperation[$op.Operation] = $userHasOperation[$op.Operation] -or $matches
            }
        }

        $denyAssignments = Get-AzDenyAssignment -Scope $Scope -SignInName $SignInName
        foreach($denyAssignment in $denyAssignments) {
            foreach($op in $Operation) {
                $matches = $false

                if (!$op.IsDataAction) {
                    foreach($action in $denyAssignment.Actions) {
                        if ($op.Operation -like $action) {
                            $matches = $true
                            break
                        }
                    }

                    if ($matches) {
                        foreach($notAction in $denyAssignment.NotActions) {
                            if ($op.Operation -like $notAction) {
                                $matches = $false
                                break
                            }
                        }
                    }
                } else {
                    foreach($dataAction in $denyAssignment.DataActions) {
                        if ($op.Operation -like $dataAction) {
                            $matches = $true
                            break
                        }
                    }

                    if ($matches) {
                        foreach($notDataAction in $denyAssignment.NotDataActions) {
                            if ($op.Operation -like $notDataAction) {
                                $matches = $false
                                break
                            }
                        }
                    }
                }

                $userHasOperation[$op.Operation] = $userHasOperation[$op.Operation] -and !$matches
            }
        }
        
        return $userHasOperation
    }
}

function Assert-AzPermission {
    #requires -Module Az.Resources

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("ResourceId", "Id")]
        [string]$Scope,

        [Parameter(Mandatory=$true, ParameterSetName="OperationsName")]
        [string[]]$OperationName,

        [Parameter(Mandatory=$true, ParameterSetName="OperationsObj")]
        [Microsoft.Azure.Commands.Resources.Models.PSResourceProviderOperation[]]$Operation
    )

    process {
        $testParams = @{}
        switch ($PSCmdlet.ParameterSetName) {
            "OperationsName" {
                $testParams += @{
                    "OperationName" = $OperationName
                }
            }

            "OperationsObj" {
                $testParams += @{
                    "Operation" = $Operation
                }
            }

            default {
                throw [ArgumentException]::new("Unrecognized parameter set $_")
            }
        }

        $permissionMatches = Test-AzPermission @testParams
        $falseValues = $permissionMatches | Where-Object { $_.Value -eq $false }
        if ($null -ne $falseValues) {
            $errorBuilder = [StringBuilder]::new()
            $errorBuilder.Append("The current user lacks the following permissions: ") | Out-Null
            for($i=0; $i -lt $falseValues.Length; $i++) {
                if ($i -gt 0) {
                    $errorBuilder.Append(", ") | Out-Null
                }

                $errorBuilder.Append($falseValues.Key) | Out-Null
            }

            $errorBuilder.Append(".") | Out-Null
            Write-Error -Message $errorBuilder.ToString() -ErrorAction Stop
        }
    }
}