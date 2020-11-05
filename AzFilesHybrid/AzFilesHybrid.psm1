using namespace System
using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.Specialized
using namespace System.Text
using namespace System.Security
param(
    [Parameter(Mandatory=$false, Position=0)]
    [hashtable]$OverrideModuleConfig = @{}
)
# This module contains many cmdlets which may be used in different scenarios. Since the purpose 
# of this module is to provide cmdlets that cross the cloud/on-premises boundary, you may want 
# to take a look at what that cmdlets are doing prior to running them. For the ease of your 
# inspection, we have grouped them into several regions:
# - General cmdlets, used across multiple scenarios. These check or assert information about 
#   your environment, or wrap OS functionality (like *-OSFeature) to provide a common way of 
#   dealing with things across OS environments.
# - Azure Files Active Directory cmdlets, which make it possible to domain join your storage 
#   accounts to replace a file server.
# - General Azure cmdlets, which provide functionality that make working with Azure resources 
#   easier.
# - DNS cmdlets, which wrap Azure and on-premises DNS functions to make it possible to configure
#   DNS to access Azure resources on-premises and vice versa.
# - DFS-N cmdlets, which wrap Azure and Windows Server DFS-N to make it a more seamless process
#   to adopt Azure Files to replace on-premises file servers.
#   Share level permissions migration cmdlets, used to migrate share level permissions set on
#   local (on-rem) server  to share on Azure storage.


#region General cmdlets
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

function Assert-IsWindowsServer {
    [CmdletBinding()]
    param()

    Assert-IsWindows

    $installationType = Get-WindowsInstallationType
    if ($installationType -ne "Server" -and $installationType -ne "Server Core") {
        Write-Error `
                -Message "The cmdlet, script, or module must be run on a Windows Server installation." `
                -ErrorAction Stop
    }
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

function Assert-OSFeature {
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
            switch ((Get-WindowsInstallationType)) {
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

                default {
                    throw [PlatformNotSupportedException]::new("Windows installation type $_ is not currently supported.")
                }
            }
        }

        "Linux" {
            throw [PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [PlatformNotSupportedException]::new()
        }

        default {
            throw [PlatformNotSupportedException]::new()
        }
    }

    if ($null -ne $notFoundFeatures -and $notFoundFeatures.Length -gt 0) {
        $errorBuilder = [StringBuilder]::new()
        $errorBuilder.Append("The following features could not be found: ") | Out-Null

        $i=0
        $notFoundFeatures | ForEach-Object { 
            if ($i -gt 0) {
                $errorBuilder.Append(", ") | Out-Null
            }

            $errorBuilder.Append($_) | Out-Null
        }

        $errorBuilder.Append(".") | Out-Null
        Write-Error -Message $errorBuilder.ToString() -ErrorAction Stop
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

    $adModule = Get-Module -Name ActiveDirectory 
    if ($null -eq $adModule) {
        Import-Module -Name ActiveDirectory
    }
}

function Request-PowerShellGetModule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param()

    $psGetModule = Get-Module -Name PowerShellGet -ListAvailable | `
        Sort-Object -Property Version -Descending

    if ($null -eq $psGetModule -or $psGetModule[0].Version -lt [Version]::new(1,6,0)) {
        $caption = "Install updated version of PowerShellGet"
        $verboseConfirmMessage = "This module requires PowerShellGet 1.6.0+. This can be installed now if you are running as an administrator. At the end of the installation, importing this module will fail as you must close all open instances of PowerShell for the updated version of PowerShellGet to be available."
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            if (!(Get-IsElevatedSession)) {
                Write-Error -Message "To install PowerShellGet, you must import this module as an administrator. This module package does not generally require administrator privileges, so successive imports of this module can be from a non-elevated session." -ErrorAction Stop
            }

            try {
                Remove-Module -Name PowerShellGet, PackageManagement -Force -ErrorAction SilentlyContinue
                Install-PackageProvider -Name NuGet -Force | Out-Null
    
                Install-Module `
                        -Name PowerShellGet `
                        -Repository PSGallery `
                        -Force `
                        -ErrorAction Stop `
                        -SkipPublisherCheck
            } catch {
                Write-Error -Message "PowerShellGet was not successfully installed, and is a requirement of this module. See https://docs.microsoft.com/powershell/scripting/gallery/installing-psget for information on how to manually troubleshoot the PowerShellGet installation." -ErrorAction Stop
            }             
            
            Write-Verbose -Message "Installed latest version of PowerShellGet module."
            Write-Error -Message "PowerShellGet was successfully installed, however you must close all open PowerShell sessions to use the new version. The next import of this module will be able to use PowerShellGet." -ErrorAction Stop
        }
    }

    Remove-Module -Name PowerShellGet -ErrorAction SilentlyContinue
    Remove-Module -Name PackageManagement -ErrorAction SilentlyContinue
}

function Request-AzureADModule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param()

    if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0)) {
        $winCompat = Get-Module -Name WindowsCompatibility -ListAvailable
    }

    $azureADModule = Get-Module -Name AzureAD -ListAvailable
    if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0) -and $null -ne $winCompat) {
        $azureADModule = Invoke-WinCommand -Verbose:$false -ScriptBlock { 
            Get-Module -Name AzureAD -ListAvailable 
        }
    }

    if (
        ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0,0) -and $null -eq $winCompat) -or 
        $null -eq $azureADModule
    ) {
        $caption = "Install AzureAD PowerShell module"
        $verboseConfirmMessage = "This cmdlet requires the Azure AD PowerShell module. This can be automatically installed now if you are running in an elevated sessions."
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            if (!(Get-IsElevatedSession)) {
                Write-Error `
                        -Message "To install AzureAD, you must run this cmdlet as an administrator. This cmdlet may not generally require administrator privileges." `
                        -ErrorAction Stop
            }

            if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0) -and $null -eq $winCompat) {
                Install-Module `
                        -Name WindowsCompatibility `
                        -Repository PSGallery `
                        -AllowClobber `
                        -Force `
                        -ErrorAction Stop

                Import-Module -Name WindowsCompatibility
            }
            
            $scriptBlock = { 
                $azureADModule = Get-Module -Name AzureAD -ListAvailable
                if ($null -eq $azureADModule) {
                    Install-Module `
                            -Name AzureAD `
                            -Repository PSGallery `
                            -AllowClobber `
                            -Force `
                            -ErrorAction Stop
                }
            }

            if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0)) {
                Invoke-WinCommand `
                        -ScriptBlock $scriptBlock `
                        -Verbose:$false `
                        -ErrorAction Stop
            } else {
                $scriptBlock.Invoke()
            }
        }
    }

    Remove-Module -Name PowerShellGet -ErrorAction SilentlyContinue
    Remove-Module -Name PackageManagement -ErrorAction SilentlyContinue
}

function Request-AzPowerShellModule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param()

    # There is an known issue where versions less than PS 6.2 don't have the Az rollup module installed:
    # https://github.com/Azure/azure-powershell/issues/9835 
    if ($PSVersionTable.PSVersion -gt [Version]::new(6,2)) {
        $azModule = Get-Module -Name Az -ListAvailable
    } else {
        $azModule = Get-Module -Name Az.* -ListAvailable
    }

    $storageModule = Get-Module -Name Az.Storage -ListAvailable | `
        Where-Object { 
            $_.Version -ge [Version]::new(2,0,0) 
        }

    # Do should process if modules must be installed
    if ($null -eq $azModule -or $null -eq $storageModule) {
        $caption = "Install Azure PowerShell modules"
        $verboseConfirmMessage = "This module requires Azure PowerShell (`"Az`" module) 2.8.0+ and Az.Storage 2.0.0+. This can be installed now if you are running as an administrator."
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            if (!(Get-IsElevatedSession)) {
                Write-Error `
                        -Message "To install the required Azure PowerShell modules, you must run this module as an administrator. This module does not generally require administrator privileges." `
                        -ErrorAction Stop
            }

            if ($null -eq $azModule) {
                Get-Module -Name Az.* | Remove-Module
                Install-Module -Name Az -Repository PSGallery -AllowClobber -Force -ErrorAction Stop
                Write-Verbose -Message "Installed latest version of Az module."
            }

            if ($null -eq $storageModule) {
                Remove-Module `
                        -Name Az.Storage `
                        -Force `
                        -ErrorAction SilentlyContinue
                
                try {
                    Uninstall-Module `
                            -Name Az.Storage `
                            -Force `
                            -ErrorAction SilentlyContinue
                } catch {
                    Write-Error `
                            -Message "Unable to uninstall the existing Az.Storage module which has a version lower than 2.0.0." `
                            -ErrorAction Stop
                }

                Install-Module `
                        -Name Az.Storage `
                        -Repository PSGallery `
                        -AllowClobber `
                        -Force `
                        -MinimumVersion "2.0.0" `
                        -SkipPublisherCheck `
                        -ErrorAction Stop
            }       
        }
    }
    
    Remove-Module -Name PowerShellGet -ErrorAction SilentlyContinue
    Remove-Module -Name PackageManagement -ErrorAction SilentlyContinue
    Remove-Module -Name Az.Storage -Force -ErrorAction SilentlyContinue
    Remove-Module -Name Az.Accounts -Force -ErrorAction SilentlyContinue
    Remove-Module -Name Az.Network -Force -ErrorAction SilentlyContinue

    $storageModule = ,(Get-Module -Name Az.Storage -ListAvailable | `
        Where-Object { 
            $_.Version -ge [Version]::new(2,0,0) 
        } | `
        Sort-Object -Property Version -Descending)

    Import-Module -ModuleInfo $storageModule[0] -Global -ErrorAction Stop
    Import-Module -Name Az.Network -Global -ErrorAction Stop
}

function Assert-DotNetFrameworkVersion {
    <#
    .SYNOPSIS
    Require a particular .NET Framework version or throw an error if it's not available. 

    .DESCRIPTION
    This cmdlet makes it possible to throw an error if a particular .NET Framework version is not installed on Windows. It wraps the registry using the information about .NET Framework here: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#query-the-registry-using-code. This cmdlet is not PowerShell 5.1 only, since it's reasonable to imagine a case where a PS6+ cmdlet/module would want to require a particular version of .NET.

    .PARAMETER DotNetFrameworkVersion
    The minimum version of .NET Framework to require. If a newer version is found, that will satisify the request.

    .EXAMPLE 
    Assert-DotNetFrameworkVersion
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "Framework4.5", 
            "Framework4.5.1",
            "Framework4.5.2", 
            "Framework4.6", 
            "Framework4.6.1", 
            "Framework4.6.2", 
            "Framework4.7", 
            "Framework4.7.1", 
            "Framework4.7.2", 
            "Framework4.8")]
        [string]$DotNetFrameworkVersion
    )

    Assert-IsWindows

    $v4 = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" | `
        Where-Object { $_.PSChildName -eq "v4" }
    if ($null -eq $v4) {
        Write-Error `
                -Message "This module/cmdlet requires at least .NET 4.0 to be installed." `
                -ErrorAction Stop
    }

    $full = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4" | `
        Where-Object { $_.PSChildName -eq "Full" }
    if ($null -eq $full) {
        Write-Error `
                -Message "This module/cmdlet requires at least .NET 4.5 to be installed." `
                -ErrorAction Stop
    }

    $release = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | `
        Select-Object -ExpandProperty Release
    if ($null -eq $release) {
        Write-Error `
                -Message "The Release property is not set at HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full." `
                -ErrorAction Stop
    }

    $minimumVersionMet = $false

    # Logic taken from: https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#query-the-registry-using-code
    switch($DotNetFrameworkVersion) {
        "Framework4.5" {
            if ($release -ge 378389) {
                $minimumVersionMet = $true
            }
        }

        "Framework4.5.1" {
            if ($release -ge 378675) {
                $minimumVersionMet = $true
            }
        }

        "Framework4.5.2" {
            if ($release -ge 379893) {
                $minimumVersionMet = $true
            }
        }

        "Framework4.6" {
            if ($release -ge 393295) {
                $minimumVersionMet = $true
            }
        }

        "Framework4.6.1" {
            if ($release -ge 394254) {
                $minimumVersionMet = $true
            }
        } 

        "Framework4.6.2" {
            if ($release -ge 394802) {
                $minimumVersionMet = $true
            }
        } 

        "Framework4.7" {
            if ($release -ge 460798) {
                $minimumVersionMet = $true
            }
        } 

        "Framework4.7.1" {
            if ($release -ge 461308) {
                $minimumVersionMet = $true
            }
        } 
        
        "Framework4.7.2" {
            if ($release -ge 461808) {
                $minimumVersionMet = $true
            }
        }
            
        "Framework4.8" {
            if ($release -ge 528040) {
                $minimumVersionMet = $true
            }
        }
    }

    if (!$minimumVersionMet) {
        Write-Error `
                -Message "This module/cmdlet requires at least .NET $DotNetFrameworkVersion to be installed. Please upgrade to the newest .NET Framework available." `
                -ErrorAction Stop
    }
}

# This class is a wrapper around SecureString and StringBuilder to provide a consistent interface 
# (Append versus AppendChar) and specialized object return (give a string when StringBuilder, 
# SecureString when SecureString) so you don't have to care what the underlying object is. 
class OptionalSecureStringBuilder {
    hidden [SecureString]$SecureString
    hidden [StringBuilder]$StringBuilder
    hidden [bool]$IsSecureString

    # Create an OptionalSecureStringBuilder with the desired underlying object.
    OptionalSecureStringBuilder([bool]$isSecureString) {
        $this.IsSecureString = $isSecureString
        if ($this.IsSecureString) {
            $this.SecureString = [SecureString]::new()
        } else {
            $this.StringBuilder = [StringBuilder]::new()
        }
    }
    
    # Append a string to the internal object.
    [void]Append([string]$append) {
        if ($this.IsSecureString) {
            foreach($c in $append) {
                $this.SecureString.AppendChar($c)
            }
        } else {
            $this.StringBuilder.Append($append) | Out-Null
        }
    }

    # Get the actual object you've been writing to.
    [object]GetInternalObject() {
        if ($this.IsSecureString) {
            return $this.SecureString
        } else {
            return $this.StringBuilder.ToString()
        }
    }
}

function Get-RandomString {
    <#
    .SYNOPSIS
    Generate a random string for the purposes of password generation or random characters for unique names.

    .DESCRIPTION
    Generate a random string for the purposes of password generation or random characters for unique names.

    .PARAMETER StringLength
    The length of the string to generate.

    .PARAMETER AlphanumericOnly
    The string should only include alphanumeric characters.

    .PARAMETER CaseSensitive
    Distinguishes between the same characters of different case. 

    .PARAMETER IncludeSimilarCharacters
    Include characters that might easily be mistaken for each other (depending on the font): 1, l, I.

    .PARAMETER ExcludeCharacters
    Don't include these characters in the random string.
    
    .PARAMETER AsSecureString
    Return the object as a secure string rather than a regular string.

    .EXAMPLE
    Get-RandomString -StringLength 10 -AlphanumericOnly -AsSecureString

    .OUTPUTS
    System.String
    System.Security.SecureString
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$StringLength,

        [Parameter(Mandatory=$false)]
        [switch]$AlphanumericOnly,

        [Parameter(Mandatory=$false)]
        [switch]$CaseSensitive,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeSimilarCharacters,

        [Parameter(Mandatory=$false)]
        [string[]]$ExcludeCharacters,

        [Parameter(Mandatory=$false)]
        [switch]$AsSecureString
    )

    $characters = [string[]]@()

    $characters += 97..122 | ForEach-Object { [char]$_ }
    if ($CaseSensitive) {
        $characters += 65..90 | ForEach-Object { [char]$_ }
    }

    $characters += 0..9 | ForEach-Object { $_.ToString() }
    
    if (!$AlphanumericOnly) {
        $characters += 33..46 | ForEach-Object { [char]$_ }
        $characters += 91..96 | ForEach-Object { [char]$_ }
        $characters += 123..126 | ForEach-Object { [char]$_ }
    }

    if (!$IncludeSimilarCharacters) {
        $ExcludeCharacters += "1", "l", "I", "0", "O"
    }

    $characters = $characters | Where-Object { $_ -notin $ExcludeCharacters }

    $acc = [OptionalSecureStringBuilder]::new($AsSecureString)
    for($i=0; $i -lt $StringLength; $i++) {
        $random = Get-Random -Minimum 0 -Maximum $characters.Length
        $acc.Append($characters[$random])
    }

    return $acc.GetInternalObject()
}

function Get-ADDomainInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$Server
    )

    process {
        switch((Get-OSPlatform)) {
            "Windows" {
                $parameters = @{}

                if (![string]::IsNullOrEmpty($Identity)) {
                    $parameters += @{ "Identity" = $Identity }
                }

                if ($null -ne $Credential) {
                    $parameters += @{ "Credential" = $Credential }
                }

                if (![string]::IsNullOrEmpty($Server)) {
                    $parameters += @{ "Server" = $Server }
                }

                return Get-ADDomain @parameters
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

function Get-ADComputerInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ParameterSetName="FilterParameterSet")]
        [string]$Filter,

        [Parameter(Mandatory=$true, ParameterSetName="IdentityParameterSet")]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,
        
        [Parameter(Mandatory=$false)]
        [string]$Server
    )

    switch ((Get-OSPlatform)) {
        "Windows" {
            $parameters = @{}

            if (![string]::IsNullOrEmpty($Filter)) {
                $parameters += @{ "Filter" = $Filter }
            }

            if (![string]::IsNullOrEmpty($Identity)) {
                $parameters += @{ "Identity" = $Identity }
            }

            if ($null -ne $Properties) {
                $parameters += @{ "Properties" = $Properties }
            }

            if (![string]::IsNullOrEmpty($Server)) {
                $parameters += @{ "Server" = $Server }
            }

            return Get-ADComputer @parameters
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

function ConvertTo-EncodedJson {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [object]$Object,

        [Parameter(Mandatory=$false)]
        [int]$Depth = 2
    )

    $Object = ($Object | ConvertTo-Json -Compress -Depth $Depth).
        Replace("`"", "*").
        Replace("[", "<").
        Replace("]", ">").
        Replace("{", "^").
        Replace("}", "%")
    
    return $Object
}

function ConvertFrom-EncodedJson {
    [CmdletBinding()]
    
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
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OdjBlob,

        [Parameter(Mandatory=$true)]
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

function Register-OfflineMachine {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$MachineName,
        
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$MachineOU,

        [Parameter(Mandatory=$false)]
        [string]$DCName,
        
        [Parameter(Mandatory=$false)]
        [switch]$Reuse,

        [Parameter(Mandatory=$false)]
        [switch]$NoSearch,
        
        [Parameter(Mandatory=$false)]
        [switch]$DefaultPassword,

        [Parameter(Mandatory=$false)]
        [switch]$RootCACertificates,

        [Parameter(Mandatory=$false)]
        [string]$CertificateTemplate,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyNames,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyPaths,
        
        [Parameter(Mandatory=$false)]
        [string]$Netbios,
        
        [Parameter(Mandatory=$false)]
        [string]$PersistentSite,

        [Parameter(Mandatory=$false)]
        [string]$DynamicSite,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryDNS
    )

    process {
        $properties = @{}

        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = Get-ADDomainInternal | `
                Select-Object -ExpandProperty DNSRoot
        } else {
            try {
                Get-ADDomainInternal -Identity $Domain | Out-Null
            } catch {
                throw [System.ArgumentException]::new(
                    "Provided domain $Domain was not found.", "Domain")
            }
        }

        $properties += @{ "Domain" = $Domain }

        if (![string]::IsNullOrEmpty($MachineName)) {
            $computer = Get-ADComputerInternal `
                    -Filter "Name -eq '$MachineName'" `
                    -Server $Domain

            if ($null -ne $computer) {
                throw [System.ArgumentException]::new(
                    "Machine $MachineName already exists.", "MachineName")
            }
        } else {
            throw [System.ArgumentException]::new(
                "The machine name property must not be empty.", "MachineName")
        }

        $properties += @{ "MachineName" = $MachineName }

        if ($PSBoundParameters.ContainsKey("MachineOU")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DCName")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("Reuse")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("NoSearch")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("DefaultPassword")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("RootCACertificates")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("CertificateTemplate")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyNames")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyPaths")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("Netbios")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("PersistentSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DynamicSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PrimaryDNS")) {
            throw [System.NotImplementedException]::new()
        }

        switch((Get-OSPlatform)) {
            "Windows" {
                return Register-OfflineMachineWindows @properties
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

function Register-OfflineMachineWindows {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$MachineName,
        
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$MachineOU,

        [Parameter(Mandatory=$false)]
        [string]$DCName,
        
        [Parameter(Mandatory=$false)]
        [switch]$Reuse,

        [Parameter(Mandatory=$false)]
        [switch]$NoSearch,
        
        [Parameter(Mandatory=$false)]
        [switch]$DefaultPassword,

        [Parameter(Mandatory=$false)]
        [switch]$RootCACertificates,

        [Parameter(Mandatory=$false)]
        [string]$CertificateTemplate,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyNames,

        [Parameter(Mandatory=$false)]
        [string[]]$PolicyPaths,
        
        [Parameter(Mandatory=$false)]
        [string]$Netbios,
        
        [Parameter(Mandatory=$false)]
        [string]$PersistentSite,

        [Parameter(Mandatory=$false)]
        [string]$DynamicSite,

        [Parameter(Mandatory=$false)]
        [string]$PrimaryDNS
    )

    process {
        if ($PSBoundParameters.ContainsKey("MachineOU")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DCName")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("Reuse")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("NoSearch")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("DefaultPassword")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("RootCACertificates")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("CertificateTemplate")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyNames")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PolicyPaths")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("Netbios")) {
            throw [System.NotImplementedException]::new()
        }
        
        if ($PSBoundParameters.ContainsKey("PersistentSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("DynamicSite")) {
            throw [System.NotImplementedException]::new()
        }
    
        if ($PSBoundParameters.ContainsKey("PrimaryDNS")) {
            throw [System.NotImplementedException]::new()
        }

        $sb = [System.Text.StringBuilder]::new()
        $sb.Append("djoin.exe /provision") | Out-Null

        $sb.Append(" /domain $Domain") | Out-Null
        $sb.Append(" /machine $MachineName") | Out-Null

        $tempFile = [System.IO.Path]::GetTempFileName()
        $sb.Append(" /savefile $tempFile") | Out-Null
        
        $djoinResult = Invoke-Expression -Command $sb.ToString()

        if ($djoinResult -like "*Computer provisioning completed successfully*") {
            $blobArray = [System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $tempFile))
            $blobArray = $blobArray[0..($blobArray.Length-3)]

            Remove-Item -Path $tempFile

            return [System.Text.Encoding]::Unicode.GetString($blobArray)
        } else {
            Write-Error `
                    -Message "Machine $MachineName provisioning failed. DJoin output: $djoinResult" `
                    -ErrorAction Stop
        }
    }
}

function Join-OfflineMachine {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$OdjBlob,

        [Parameter(Mandatory=$false, ParameterSetName="WindowsParameterSet")]
        [string]$WindowsPath
    )

    switch((Get-OSPlatform)) {
        "Windows" {
            if ([string]::IsNullOrEmpty($WindowsPath)) {
                $WindowsPath = $env:windir
            }

            $tempFile = [System.IO.Path]::GetTempFileName()
            Write-OdjBlob -OdjBlob $OdjBlob -Path $tempFile

            $sb = [System.Text.StringBuilder]::new()
            $sb.Append("djoin.exe /requestodj") | Out-Null
            $sb.Append(" /loadfile $tempFile") | Out-Null
            $sb.Append(" /windowspath $WindowsPath") | Out-Null
            $sb.Append(" /localos") | Out-Null

            $djoinResult = Invoke-Expression -Command $sb.ToString()
            if ($djoinResult -like "*successfully*") {
                Write-Information -MessageData "Machine successfully provisioned. A reboot is required for changes to be applied."
                Remove-Item -Path $tempFile
            } else {
                Write-Error `
                        -Message "Machine failed to provision. DJoin output: $djoinResult" `
                        -ErrorAction Stop
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

function New-RegistryItem {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$ParentPath,

        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    Assert-IsWindows

    $ParentPath = $args[0]
    $Name = $args[1]

    $regItem = Get-ChildItem -Path $ParentPath | `
        Where-Object { $_.PSChildName -eq $Name }
    
    if ($null -eq $regItem) {
        New-Item -Path ($ParentPath + "\" + $Name) | `
            Out-Null
    }
}

function New-RegistryItemProperty {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    Assert-IsWindows

    $regItemProperty = Get-ItemProperty -Path $Path | `
        Where-Object { $_.Name -eq $Name }
    
    if ($null -eq $regItemProperty) {
        New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value | `
            Out-Null
    } else {
        Set-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value | `
            Out-Null
    }
}

function Resolve-DnsNameInternal {
    [CmdletBinding()]
    
    param(
        [Parameter(
            Mandatory=$true, 
            Position=0, 
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)]
        [string]$Name
    )

    process {
        switch((Get-OSPlatform)) {
            "Windows" {
                return (Resolve-DnsName -Name $Name)
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

function Resolve-PathRelative {
    [CmdletBinding()]

    param(
        [Parameter(
            Mandatory=$true, 
            Position=0)]
        [string[]]$PathParts
    )

    return [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine($PathParts))
}

function Get-CurrentModule {
    [CmdletBinding()]
    param()

    $ModuleInfo = Get-Module | Where-Object { $_.Path -eq $PSCommandPath }
    if ($null -eq $moduleInfo) {
        throw [System.IO.FileNotFoundException]::new(
            "Could not find a loaded module with the indicated filename.", $PSCommandPath)
    }

    return $ModuleInfo
}

function Get-ModuleFiles {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory = $false, ValueFromPipeline=$true)]
        [System.Management.Automation.PSModuleInfo]$ModuleInfo
    )

    process {
        $moduleFiles = [System.Collections.Generic.HashSet[string]]::new()

        if (!$PSBoundParameters.ContainsKey("ModuleInfo")) {
            $ModuleInfo = Get-CurrentModule
        }
    
        $manifestPath = Resolve-PathRelative `
                -PathParts $ModuleInfo.ModuleBase, "$($moduleInfo.Name).psd1"
        
        if (!(Test-Path -Path $manifestPath)) {
            throw [System.IO.FileNotFoundException]::new(
                "Could not find a module manifest with the indicated filename", $manifestPath)
        }
        
        try {
            $manifest = Import-PowerShellDataFile -Path $manifestPath
        } catch {
            throw [System.IO.FileNotFoundException]::new(
                "File matching name of manifest found, but does not contain module manifest.", $manifestPath)
        }
    
        $moduleFiles.Add($manifestPath) | Out-Null
        $moduleFiles.Add((Resolve-PathRelative `
                -PathParts $ModuleInfo.ModuleBase, $manifest.RootModule)) | `
            Out-Null
        
        if ($null -ne $manifest.NestedModules) {
            foreach($nestedModule in $manifest.NestedModules) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $nestedModule)) | `
                    Out-Null
            }
        }
        
        if ($null -ne $manifest.FormatsToProcess) {
            foreach($format in $manifest.FormatsToProcess) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $format)) | `
                    Out-Null
            }
        }
    
        if ($null -ne $manifest.RequiredAssemblies) {
            foreach($assembly in $manifest.RequiredAssemblies) {
                $moduleFiles.Add((Resolve-PathRelative `
                        -PathParts $ModuleInfo.ModuleBase, $assembly)) | `
                    Out-Null
            }
        }

        return $moduleFiles
    }
}

function Copy-RemoteModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $moduleInfo = Get-CurrentModule
    $moduleFiles = Get-ModuleFiles | `
        Get-Item | `
        Select-Object `
            @{ Name = "Name"; Expression = { $_.Name } }, 
            @{ Name = "Content"; Expression = { (Get-Content -Path $_.FullName) } }

    Invoke-Command `
            -Session $Session  `
            -ArgumentList $moduleInfo.Name, $moduleInfo.Version.ToString(), $moduleFiles `
            -ScriptBlock {
                $moduleName = $args[0]
                $moduleVersion = $args[1]
                $moduleFiles = $args[2]

                $psModPath = $env:PSModulePath.Split(";")[0]
                if (!(Test-Path -Path $psModPath)) {
                    New-Item -Path $psModPath -ItemType Directory | Out-Null
                }

                $modulePath = [System.IO.Path]::Combine(
                    $psModPath, $moduleName, $moduleVersion)
                if (!(Test-Path -Path $modulePath)) {
                    New-Item -Path $modulePath -ItemType Directory | Out-Null
                }

                foreach($moduleFile in $moduleFiles) {
                    $filePath = [System.IO.Path]::Combine($modulePath, $moduleFile.Name)
                    $fileContent = $moduleFile.Content
                    Set-Content -Path $filePath -Value $fileContent
                }
            }
}

$sessionDictionary = [System.Collections.Generic.Dictionary[System.Tuple[string, string], System.Management.Automation.Runspaces.PSSession]]::new()
function Initialize-RemoteSession {
    [CmdletBinding()]
    
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Copy-Session")]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory=$true, ParameterSetName="Copy-ComputerName")]
        [string]$ComputerName,

        [Parameter(Mandatory=$false, ParameterSetName="Copy-ComputerName")]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$true, ParameterSetName="Copy-Session")]
        [Parameter(Mandatory=$true, ParameterSetName="Copy-ComputerName")]
        [switch]$InstallViaCopy,

        [Parameter(Mandatory=$false, ParameterSetName="Copy-Session")]
        [Parameter(Mandatory=$false, ParameterSetName="Copy-ComputerName")]
        [hashtable]$OverrideModuleConfig = @{}
    )

    $paramSplit = $PSCmdlet.ParameterSetName.Split("-")
    $ScriptCopyBehavior = $paramSplit[0]
    $SessionBehavior = $paramSplit[1]

    switch($SessionBehavior) {
        "Session" { 
            $ComputerName = $session.ComputerName
            $username = Invoke-Command -Session $Session -ScriptBlock {
                $(whoami).ToLowerInvariant()
            }
        }

        "ComputerName" {
            $sessionParameters = @{ "ComputerName" = $ComputerName }
            
            if ($PSBoundParameters.ContainsKey("Credential")) {
                $sessionParameters += @{ "Credential" = $Credential }
                $username = $Credential.UserName
            } else {
                $username = $(whoami).ToLowerInvariant()
            }

            $Session = New-PSSession @sessionParameters
        }

        default {
            throw [System.ArgumentException]::new(
                "Unrecognized session parameter set.", "SessionBehavior")
        }
    }
    
    $lookupTuple = [System.Tuple[string, string]]::new($ComputerName, $username)
    $existingSession = [System.Management.Automation.Runspaces.PSSession]$null
    if ($sessionDictionary.TryGetValue($lookupTuple, [ref]$existingSession)) {
        if ($existingSession.State -ne "Opened") {
            $sessionDictionary.Remove($existingSession)

            Remove-PSSession `
                    -Session $existingSession `
                    -WarningAction SilentlyContinue `
                    -ErrorAction SilentlyContinue
            
            $sessionDictionary.Add($lookupTuple, $Session)
        } else {
            Remove-PSSession `
                -Session $Session `
                -WarningAction SilentlyContinue `
                -ErrorAction SilentlyContinue

            $Session = $existingSession
        }
    } else {
        $sessionDictionary.Add($lookupTuple, $Session)
    }

    $moduleInfo = Get-CurrentModule
    $remoteModuleInfo = Get-Module `
            -PSSession $Session `
            -Name $moduleInfo.Name `
            -ListAvailable
    
    switch($ScriptCopyBehavior) {
        "Copy" {
            if ($null -eq $remoteModuleInfo) {
                Copy-RemoteModule -Session $Session
            } elseif ($moduleInfo.Version -ne $remoteModuleInfo.Version) {
                Write-Error `
                        -Message "There is already a version of this module installed on the destination machine $($Session.ComputerName)" `
                        -ErrorAction Stop
            }
        }

        default {
            throw [System.ArgumentException]::new(
                "Unrecognized session parameter set.", "ScriptCopyBehavior")
        }
    }

    Invoke-Command `
            -Session $Session `
            -ArgumentList $moduleInfo.Name, $OverrideModuleConfig `
            -ScriptBlock {
                $moduleName = $args[0]
                $OverrideModuleConfig = $args[1]
                Import-Module -Name $moduleName -ArgumentList $OverrideModuleConfig
                Invoke-Expression -Command "using module $moduleName"
            }

    return $Session
}
#endregion


#region Azure Files Active Directory cmdlets
function Validate-StorageAccount {
    [CmdletBinding()]
    param (
         [Parameter(Mandatory=$true, Position=0)]
         [string]$ResourceGroupName,
         [Parameter(Mandatory=$true, Position=1)]
         [string]$StorageAccountName
    )

    process
    {
        $resourceGroupObject = Get-AzResourceGroup -Name $ResourceGroupName

        if ($null -eq $resourceGroupObject)
        {
            $message = "Resource group not found: '$ResourceGroupName'." `
                + " Please check whether the provided name '$ResourceGroupName' is valid or" `
                + " whether the resource group exists by running" `
                + " 'Get-AzResourceGroup -Name <ResourceGroupName>'" `
                + " (https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell)"
            Write-Error -Message $message -ErrorAction Stop
        }

        $storageAccountObject = Get-AzStorageAccount -ResourceGroup $ResourceGroupName -Name $StorageAccountName

        if ($null -eq $storageAccountObject)
        {
            $message = "Storage account not found: '$StorageAccountName'." `
                + " Please check whether the provided name '$StorageAccountName' is valid or" `
                + " whether the storage account exists by running" `
                + " 'Get-AzStorageAccount -ResourceGroup <ResourceGroupName> -Name <StorageAccountName>'" `
                + " (https://docs.microsoft.com/en-us/powershell/module/az.storage/get-azstorageaccount?view=azps-4.4.0)"
            Write-Error -Message $message -ErrorAction Stop
        }

        Write-Verbose "Found storage Account '$StorageAccountName' in Resource Group '$ResourceGroupName'"

        return $storageAccountObject
    }
}

function Ensure-KerbKeyExists {
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
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        }
        catch {
            Write-Error -Message "Caught exception: $_" -ErrorAction Stop
        }

        try {
            $keys = Get-AzStorageAccountKerbKeys -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
            $kerb1Key = $keys | Where-Object { $_.KeyName -eq "kerb1" }
            $kerb2Key = $keys | Where-Object { $_.KeyName -eq "kerb2" }
        }
        catch {
            Write-Verbose "Caught exception: $($_.Exception.Message)"
        }

        if ($null -eq $kerb1Key) {
            #
            # The storage account doesn't have kerb keys yet.  Generate them now.
            #

            try {
                $keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb1 -ErrorAction Stop
            }
            catch {
                Write-Error -Message "Caught exception: $_" -ErrorAction Stop
            }

            $kerb1Key = Get-AzStorageAccountKerbKeys -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName `
                        | Where-Object { $_.KeyName -eq "kerb1" }
        
            Write-Verbose "    Key: $($kerb1Key.KeyName) generated for StorageAccount: $StorageAccountName"
        } else {
            Write-Verbose "    Key: $($kerb1Key.KeyName) exists in Storage Account: $StorageAccountName"
        }

        if ($null -eq $kerb2Key) {
            #
            # The storage account doesn't have kerb keys yet.  Generate them now.
            #

            $keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb2 -ErrorAction Stop

            $kerb2Key = Get-AzStorageAccountKerbKeys -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName `
                        | Where-Object { $_.KeyName -eq "kerb2" }
        
            Write-Verbose "    Key: $($kerb2Key.KeyName) generated for StorageAccount: $StorageAccountName"
        } else {
            Write-Verbose "    Key: $($kerb2Key.KeyName) exists in Storage Account: $StorageAccountName"
        }
    }
}

function Get-AzStorageAccountFileEndpoint {
    <#
    .SYNOPSIS
        Gets the file service endpoint for the storage account.
    
    .DESCRIPTION
        Gets the file service endpoint for the storage account.
        Notably, this command queries the storage account's file endpoint URL
        (i.e. "https://<storageAccount>.file.core.windows.net/") and returns it.
    .EXAMPLE
        PS C:\> Get-AzStorageAccountFileEndpoint -storageAccountName "storageAccount" -resourceGroupName "resourceGroup"
        https://<storageAccount>.file.core.windows.net/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName
    )

    $storageAccountObject = Validate-StorageAccount -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName -ErrorAction Stop

    if ([string]::IsNullOrEmpty($storageAccountObject.PrimaryEndpoints.File)) {
        $message = "Cannot find the file service endpoint for storage account" `
            + " '$StorageAccountName' in resource group '$ResourceGroupName'. This may happen" `
            + " if the storage account type does not support file service" `
            + " (https://docs.microsoft.com/en-us/azure/storage/common/storage-account-overview#types-of-storage-accounts)."
        Write-Error -Message $message -ErrorAction Stop
    }

    return $storageAccountObject.PrimaryEndpoints.File
}

function Get-AzStorageAccountActiveDirectoryProperties {
    <#
    .SYNOPSIS
        Gets the active directory properties for the storage account.
    
    .DESCRIPTION
        Gets the active directory properties for the storage account.
        Notably, this command queries the storage account's AzureFilesIdentityBasedAuth.ActiveDirectoryProperties and returns it.
    .EXAMPLE
        PS C:\> Get-AzStorageAccountActiveDirectoryProperties -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [string]$StorageAccountName,

        [Parameter(
            Mandatory=$true, 
            Position=0, 
            ParameterSetName="StorageAccount", 
            ValueFromPipeline=$true)]
        [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount
    )

    switch ($PSCmdlet.ParameterSetName) {
        "StorageAccountName" {
            $StorageAccount = Validate-StorageAccount -ResourceGroupName $ResourceGroupName `
                -StorageAccountName $StorageAccountName -ErrorAction Stop
        }

        "StorageAccount" {                
            $ResourceGroupName = $StorageAccount.ResourceGroupName
            $StorageAccountName = $StorageAccount.StorageAccountName
        }

        default {
            throw [ArgumentException]::new("Unrecognized parameter set $_")
        }
    }

    if ($null -eq $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties) {
        $message = "ActiveDirectoryProperties is not set for storage account '$StorageAccountName'" `
            + " in resource group '$ResourceGroupName'. To set the properties, please use cmdlet" `
            + " Set-AzStorageAccount if the account is already associated with an Active Directory," `
            + " or use cmdlet Join-AzStorageAccountForAuth to join the account to an Active Directory" `
            + " (https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-enable)"
        Write-Error -Message $message -ErrorAction Stop
    }

    return $StorageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
}

function Get-AzStorageAccountKerbKeys {
    <#
    .SYNOPSIS
        Gets the kerb keys for the storage account.
    
    .DESCRIPTION
        Gets the kerb keys for the storage account.
    .EXAMPLE
        PS C:\> Get-AzStorageAccountKerbKeys -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$StorageAccountName
    )

    Validate-StorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
    
    $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey `
            | Where-Object { $_.KeyName -like "kerb*" }

    if (($null -eq $keys) -or (($keys -is [System.Array]) -and ($keys.Length -eq 0))) {
        $message = "Cannot find kerb keys for storage account '$StorageAccountName' in" `
            + " resource group '$ResourceGroupName'. Please ensure kerb keys are configured" `
            + " (https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-enable#creating-an-identity-representing-the-storage-account-in-your-ad-manually)"
        Write-Error -Message $message -ErrorAction Stop
    }

    return $keys
}

function Get-ServicePrincipalName {
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
        PS C:\> Get-ServicePrincipalName -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup"
        cifs\storageAccount.file.core.windows.net
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName
    )

    $fileEndpoint = Get-AzStorageAccountFileEndpoint -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName -ErrorAction Stop

    $servicePrincipalName = $fileEndpoint -replace 'https://','cifs/'
    $servicePrincipalName = $servicePrincipalName.TrimEnd('/')

    if ([string]::IsNullOrEmpty($servicePrincipalName)) {
        $message = "Unable to generate the service principal name from the" `
            + " storage account's file endpoint '$fileEndpoint'"
        Write-Error -Message $message -ErrorAction Stop
    }

    Write-Verbose "Generated service principal name of $servicePrincipalName"
    return $servicePrincipalName
}

function New-ADAccountForStorageAccount {
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
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ADObjectName,

        [Parameter(Mandatory=$true, Position=1, HelpMessage="Storage account name")]
        [string]$StorageAccountName, 

        [Parameter(Mandatory=$true, Position=2, HelpMessage="Resource group name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$false, Position=3)]
        [string]$Domain,

        [Parameter(Mandatory=$false, Position=4)]
        # [Parameter(Mandatory=$false, Position=4, ParameterSetName="OUQuickName")]
        [string]$OrganizationalUnit,

        [Parameter(Mandatory=$false, Position=4)]
        # [Parameter(Mandatory=$false, Position=4, ParameterSetName="OUDistinguishedName")]
        [string]$OrganizationalUnitDistinguishedName,

        [Parameter(Mandatory=$false, Position=5)]
        [ValidateSet("ServiceLogonAccount", "ComputerAccount")]
        [string]$ObjectType = "ComputerAccount",

        [Parameter(Mandatory=$false, Position=6)]
        [switch]$OverwriteExistingADObject
    )

    Assert-IsWindows
    Assert-IsDomainJoined
    Request-ADFeature

    Write-Verbose -Message "ObjectType: $ObjectType"

    if ([System.String]::IsNullOrEmpty($Domain)) {
        if ($ObjectType -ieq "ComputerAccount") {
            $domainInfo = Get-ADDomain -Current LocalComputer
        } else { # "ServiceLogonAccount"
            $domainInfo = Get-ADDomain -Current LoggedOnUser
        }

        $Domain = $domainInfo.DnsRoot
        $path = $domainInfo.DistinguishedName
    } else {
        try {
            $path = ((Get-ADDomain -Server $Domain).DistinguishedName)
        }
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            Write-Error -Message "The specified domain '$Domain' either does not exist or could not be contacted." -ErrorAction Stop
        }
        catch {
            throw
        }
    }

    if (-not ($PSBoundParameters.ContainsKey("OrganizationalUnit") -or $PSBoundParameters.ContainsKey("OrganizationalUnitDistinguishedName"))) {
        if ($ObjectType -ieq "ComputerAccount") {
            $currentComputer = Get-ADComputer -Identity $($Env:COMPUTERNAME) -Server $Domain

            if ($null -eq $currentComputer) {
                Write-Error -Message "Could not find computer '$($Env:COMPUTERNAME)' in domain '$Domain'" -ErrorAction Stop
            }

            $OrganizationalUnitDistinguishedName = $currentComputer.DistinguishedName.Substring($currentComputer.DistinguishedName.IndexOf(',') + 1)
        } else { # "ServiceLogonAccount"
            $currentUser = Get-ADUser -Identity $($Env:USERNAME) -Server $Domain

            if ($null -eq $currentUser) {
                Write-Error -Message "Could not find user '$($Env:USERNAME)' in domain '$Domain'" -ErrorAction Stop
            }

            $OrganizationalUnitDistinguishedName = $currentUser.DistinguishedName.Substring($currentUser.DistinguishedName.IndexOf(',') + 1)
        }
    }

    if (-not [System.String]::IsNullOrEmpty($OrganizationalUnitDistinguishedName)) {
        $ou = Get-ADObject -Identity $OrganizationalUnitDistinguishedName -Server $Domain

        if ($null -eq $ou) {
            Write-Error -Message "Could not find an object with name '$OrganizationalUnitDistinguishedName' in the $Domain domain" -ErrorAction Stop
        }
    } elseif (-not [System.String]::IsNullOrEmpty($OrganizationalUnit)) {
        $ou = Get-ADObject -Filter "Name -eq '$OrganizationalUnit'" -Server $Domain

        if ($null -eq $ou) {
            Write-Error -Message "Could not find an object with name '$OrganizationalUnit' in the $Domain domain" -ErrorAction Stop
        }

        if ($ou -is ([object[]])) {
            $ouNames = $ou | Select-Object -Property DistinguishedName -ExpandProperty DistinguishedName
            $message = [System.Text.StringBuilder]::new()
            $message.AppendLine("Multiple OrganizationalUnits were found matching the name '$OrganizationalUnit':")
            $ouNames | ForEach-Object { $message.AppendLine($_) }
            $message.AppendLine("To disambiguate the OU you want to join the storage account to, use the OrganizationalUnitDistinguishedName parameter.")
            Write-Error -Message $message.ToString() -ErrorAction Stop
        }
    } else {
        Write-Error -Message "Missing parameter OrganizationalUnit or OrganizationalUnitDistinguishedName" -ErrorAction Stop
    }
    
    $path = $ou.DistinguishedName

    Write-Verbose "New-ADAccountForStorageAccount: Creating a AD account under $path in domain:$Domain to represent the storage account:$StorageAccountName"

    #
    # Get the kerb key and convert it to a secure string password.
    #

    $kerb1Key = Get-AzStorageAccountKerbKeys -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName `
        -ErrorAction Stop | Where-Object { $_.KeyName -eq "kerb1" };

    $fileServiceAccountPwdSecureString = ConvertTo-SecureString -String $kerb1Key.Value -AsPlainText -Force

    # Get SPN
    $spnValue = Get-ServicePrincipalName `
            -StorageAccountName $StorageAccountName `
            -ResourceGroupName $ResourceGroupName `
            -ErrorAction Stop

    # Check to see if SPN already exists
    $computerSpnMatch = Get-ADComputer `
            -Filter "ServicePrincipalNames -eq '$spnValue'" `
            -Server $Domain

    $userSpnMatch = Get-ADUser `
            -Filter "ServicePrincipalNames -eq '$spnValue'" `
            -Server $Domain

    if (($null -ne $computerSpnMatch) -and ($null -ne $userSpnMatch)) {
        $message = [System.Text.StringBuilder]::new()
        $message.AppendLine("There are already two AD objects with a Service Principal Name of $spnValue in domain $($Domain):")
        $message.AppendLine($computerSpnMatch.DistinguishedName)
        $message.AppendLine($userSpnMatch.DistinguishedName)
        $message.AppendLine("It is not supported to have more than one AD object for a given Service Principal Name. Please delete the duplicated object that is not needed and retry this cmdlet.")
        Write-Error -Message $message.ToString() -ErrorAction Stop
    } elseif ($null -ne $computerSpnMatch) {
        if ($ObjectType -ieq "ServiceLogonAccount") {
            Write-Error -Message "It is not supported to create an AD object of type 'ServiceLogonAccount' when there is already an AD object '$($computerSpnMatch.DistinguishedName)' of type 'ComputerAccount'." -ErrorAction Stop
        }

        if (-not $OverwriteExistingADObject) {
            Write-Error -Message "An AD object '$($computerSpnMatch.DistinguishedName)' with a Service Principal Name of $spnValue already exists within AD. This might happen because you are rejoining a new storage account that shares names with an existing storage account, or if the domain join operation for a storage account failed in an incomplete state. Delete this AD object (or remove the SPN) to continue or specify a switch -OverwriteExistingADObject when calling this cmdlet. See https://docs.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems for more information." -ErrorAction Stop
        }

        $ADObjectName = $computerSpnMatch.Name
        Write-Verbose -Message "Overwriting an existing AD $ObjectType object $ADObjectName with a Service Principal Name of $spnValue in domain $Domain."
    } elseif ($null -ne $userSpnMatch) {
        if ($ObjectType -ieq "ComputerAccount") {
            Write-Error -Message "It is not supported to create an AD object of type 'ComputerAccount' when there is already an AD object '$($userSpnMatch.DistinguishedName)' of type 'ServiceLogonAccount'." -ErrorAction Stop
        }

        if (-not $OverwriteExistingADObject) {
            Write-Error -Message "An AD object '$($userSpnMatch.DistinguishedName)' with a Service Principal Name of $spnValue already exists within AD. This might happen because you are rejoining a new storage account that shares names with an existing storage account, or if the domain join operation for a storage account failed in an incomplete state. Delete this AD object (or remove the SPN) to continue or specify a switch -OverwriteExistingADObject when calling this cmdlet. See https://docs.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems for more information." -ErrorAction Stop
        }

        $ADObjectName = $userSpnMatch.Name
        Write-Verbose -Message "Overwriting an existing AD $ObjectType object $ADObjectName with a Service Principal Name of $spnValue in domain $Domain."
    }

    # Create the identity in Active Directory.    
    try
    {
        switch ($ObjectType) {
            "ServiceLogonAccount" {
                Write-Verbose -Message "`$ServiceAccountName is $StorageAccountName"

                if ($null -ne $userSpnMatch) {
                    $userSpnMatch.AllowReversiblePasswordEncryption = $false
                    $userSpnMatch.PasswordNeverExpires = $true
                    $userSpnMatch.Description = "Service logon account for Azure storage account $StorageAccountName."
                    $userSpnMatch.Enabled = $true
                    $userSpnMatch.TrustedForDelegation = $true
                    Set-ADUser -Instance $userSpnMatch -ErrorAction Stop
                } else {
                    New-ADUser `
                        -SamAccountName $ADObjectName `
                        -Path $path `
                        -Name $ADObjectName `
                        -AccountPassword $fileServiceAccountPwdSecureString `
                        -AllowReversiblePasswordEncryption $false `
                        -PasswordNeverExpires $true `
                        -Description "Service logon account for Azure storage account $StorageAccountName." `
                        -ServicePrincipalNames $spnValue `
                        -Server $Domain `
                        -Enabled $true `
                        -TrustedForDelegation $true `
                        -ErrorAction Stop
                }

                #
                # Set the service principal name for the identity to be "cifs\<storageAccountName>.file.core.windows.net"
                #
                # Set-ADUser -Identity $StorageAccountName -ServicePrincipalNames @{Add=$spnValue} -ErrorAction Stop
            }

            "ComputerAccount" {
                if ($null -ne $computerSpnMatch) {
                    $computerSpnMatch.AllowReversiblePasswordEncryption = $false
                    $computerSpnMatch.Description = "Computer account object for Azure storage account $StorageAccountName."
                    $computerSpnMatch.Enabled = $true
                    Set-ADComputer -Instance $computerSpnMatch -ErrorAction Stop
                } else {
                    New-ADComputer `
                        -SAMAccountName $ADObjectName `
                        -Path $path `
                        -Name $ADObjectName `
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
    }
    catch
    {
        #
        # Give better error message when AD exception is thrown for invalid SAMAccountName length.
        #

        if ($_.Exception.GetType().Name -eq "ADException" -and $_.Exception.Message.Contains("required attribute"))
        {
            Write-Error -Message "Unable to create AD object.  Please check that you have permission to create an identity of type $ObjectType in Active Directory location path '$path' for the storage account '$StorageAccountName'"
        }

        if ($_.Exception.GetType().Name -eq "UnauthorizedAccessException")
        {
            Write-Error -Message "Access denied: You don't have permission to create an identity of type $ObjectType in Active Directory location path '$path' for the storage account '$StorageAccountName'"
        }

        throw
    }    

    Write-Verbose "New-ADAccountForStorageAccount: Complete"

    return $ADObjectName
}

function Get-AzStorageAccountADObject {
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
                $activeDirectoryProperties = Get-AzStorageAccountActiveDirectoryProperties `
                    -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
            } else {
                $activeDirectoryProperties = Get-AzStorageAccountActiveDirectoryProperties `
                    -StorageAccount $StorageAccount -ErrorAction Stop

                $ResourceGroupName = $StorageAccount.ResourceGroupName
                $StorageAccountName = $StorageAccount.StorageAccountName    
            }

            $sid = $activeDirectoryProperties.AzureStorageSid
            $Domain = $activeDirectoryProperties.DomainName

            Write-Verbose -Message "Looking for an object with SID '$sid' in domain '$Domain' for storage account '$StorageAccountName'"
            $obj = Get-ADObject -Server $Domain -Filter "objectSID -eq '$sid'" -ErrorAction Stop

            if ($null -eq $obj) {
                $message = "Cannot find an object with a SID '$sid' in domain '$Domain' for" `
                    + " storage account '$StorageAccountName' in resource group '$ResourceGroupName'." `
                    + " Please verify that the storage account has been domain-joined through the steps" `
                    + " in Microsoft documentation:" `
                    + " https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable#12-domain-join-your-storage-account"
                Write-Error -Message $message -ErrorAction Stop
            }    
        } else {
            Write-Verbose -Message "Looking for an object with name '$ADObjectName' in domain '$Domain'"
            $obj = Get-ADObject -Server $Domain -Filter "Name -eq '$ADObjectName'" -ErrorAction Stop

            if ($null -eq $obj) {
                $message = "Cannot find an object with a '$ADObjectname' in domain '$Domain'." `
                    + " Please verify that the storage account has been domain-joined through the steps" `
                    + " in Microsoft documentation:" `
                    + " https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable#12-domain-join-your-storage-account"
                Write-Error -Message $message -ErrorAction Stop
            }    
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

function Get-CmdKeyTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, Position=0, HelpMessage="CmdKey target name to search, e.g., account.file.core.windows.net")]
        [string]$TargetName
    )

    begin {
        Assert-IsWindows
    }

    Process {
        Write-Verbose "Looking for cached credential for $TargetName"

        $output = cmdkey.exe /list

        $target = New-Object PSObject

        $targetFound = $false
        $typeFound = $false
        $userFound = $false

        foreach ($line in $output)
        {
            Write-Verbose $line
            $line = $line.Trim()

            #
            # Target: Domain:target=account.file.core.windows.net
            # Type: Domain Password
            # User: Azure\account
            #

            if ($line.StartsWith("Target:") -and $line.EndsWith("target=$TargetName"))
            {
                Write-Verbose "Found target $line"
                $propName = "Target"
                $propValue = $line.Substring($propName.Length + 1).Trim()

                Add-Member -InputObject $target -MemberType NoteProperty -Name $propName -Value $propValue -ErrorAction Stop
                $targetFound = $True
            }
            elseif ($targetFound -and $line.StartsWith("Type:"))
            {
                Write-Verbose "Found type $line"
                $propName = "Type"
                $propValue = $line.Substring($propName.Length + 1).Trim()
                Add-Member -InputObject $target -MemberType NoteProperty -Name $propName -Value $propValue -ErrorAction Stop
                $typeFound = $True
            }
            elseif ($targetFound -and $typeFound -and $line.StartsWith("User:"))
            {
                Write-Verbose "Found user $line"
                $propName = "User"
                $propValue = $line.Substring($propName.Length + 1).Trim()
                Add-Member -InputObject $target -MemberType NoteProperty -Name $propName -Value $propValue -ErrorAction Stop
                $userFound = $True
                break
            }
        }

        if (-not $userFound)
        {
            $target = $null
        }
        else
        {
            Write-Verbose "Found target object"
            Write-Verbose "Target: $($target.Target)"
            Write-Verbose "Type: $($target.Type)"
            Write-Verbose "User: $($target.User)"
        }

        return $target
    }
}

function Get-AzStorageKerberosTicketStatus {
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

    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName
    )

    begin {
        Assert-IsWindows
    }

    process 
    {
        $spnValue = Get-ServicePrincipalName -StorageAccountName $StorageAccountName `
            -ResourceGroupName $ResourceGroupName -ErrorAction Stop

        Write-Verbose "Running command 'klist.exe get $spnValue'"

        $TicketsArray = klist.exe get $spnValue;
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
            Write-Verbose $line;

            if ($line -match "0xc000018b")
            {
                #
                # STATUS_NO_TRUST_SAM_ACCOUNT
                # The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.
                #

                $message = "ERROR: The domain cannot find a computer or user object for" `
                    + " storage account '$StorageAccountName'. Please verify that the storage account has been domain-joined" `
                    + " through the steps in Microsoft documentation:" `
                    + " https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable#12-domain-join-your-storage-account"
                Write-Error -Message $message -ErrorAction Stop
            }
            elseif ($line -match "0x80090342")
            {
                #
                # SEC_E_KDC_UNKNOWN_ETYPE
                # The encryption type requested is not supported by the KDC.
                #

                $message = "ERROR: Azure Files supports Kerberos authentication with" `
                    + " AD with AES256 and RC4-HMAC encryption. This error may happen when RC4-HMAC" `
                    + " is blocked by the KDC (Kerberos Key Distribution Center). It is recommended" `
                    + " to update the storage account setup to use AES256 Kerberos encryption by using cmdlet" `
                    + " Update-AzStorageAccountAuthForAES256 -ResourceGroupName '$ResourceGroupName' -StorageAccountName '$StorageAccountName'"
                Write-Error -Message $message -ErrorAction Stop
            }
            elseif ($line -match "0x80090303")
            {
                #
                # SEC_E_TARGET_UNKNOWN
                # klist failed with 0x80090303/-2146893053: The specified target is unknown or unreachable
                #

                Write-Verbose "ERROR: $line"

                $targetName = $spnValue.Split('/')[1]

                $target = Get-CmdKeyTarget -TargetName $targetName

                if ($null -eq $target)
                {
                    $message = "Unable to find the cached credential for '$targetName'." `
                        + " Original klist error 0x80090303 is unexpected."
                    Write-Error -Message $message -ErrorAction Stop
                }
                else
                {
                    Write-Verbose "Executing 'cmdkey.exe /delete:$($target.Target)'"

                    cmdkey.exe /delete:$($target.Target)
                    
                    $target = Get-CmdKeyTarget -TargetName $targetName

                    if ($null -ne $target)
                    {
                        $message = "Unable to delete the cached credential for $($target.Target)." `
                            + " Please manually delete it and retry this cmdlet."
                        Write-Error -Message $message -ErrorAction Stop
                    }

                    Write-Verbose -Message "Retrying Get-AzStorageKerberosTicketStatus with storageAccountName $StorageAccountName and resourceGroupName $ResourceGroupName"

                    return Get-AzStorageKerberosTicketStatus -StorageAccountName $StorageAccountName `
                        -ResourceGroupName $ResourceGroupName -ErrorAction Stop
                }
            }
            elseif ($line -match "^#\d")
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
                
                if ($Server -match $spnValue)
                {
                    #
                    # We found a ticket to an Azure storage account.  Check that it has valid encryption type.
                    #
                    
                    if (($KerbTicketEType -notmatch "RC4") -and ($KerbTicketEType -notmatch "AES-256"))
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
            
            'klist get $spnValue'
        and examine error code to root-cause the ticket retrieval failure.
        " -ErrorAction Stop

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

        return ,$TicketsObject;
    }
}


function Get-AadUserForSid {

    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Sid")]
        [string]$sid
    )

    Request-ConnectAzureAD

    $aadUser = Get-AzureADUser -Filter "OnPremisesSecurityIdentifier eq '$sid'"

    if ($null -eq $aadUser)
    {
        Write-Error "No Azure Active Directory user exists with OnPremisesSecurityIdentifier of the currently logged on user's SID ($sid). `
            This means that the AD user object has not synced to the AAD corresponding to the storage account.
            Mounting to Azure Files using Active Directory authentication is not supported for AD users who have not been synced to `
            AAD. " -ErrorAction Stop
    }

    return $aadUser
}


function Test-Port445Connectivity
{
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName
    )

    process
    {
        #
        # Test-NetConnection -ComputerName <storageAccount>.file.core.windows.net -Port 445
        #

        $fileEndpoint = Get-AzStorageAccountFileEndpoint -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $StorageAccountName -ErrorAction Stop

        $endpoint = $fileEndpoint -replace 'https://', ''
        $endpoint = $endpoint -replace '/', ''

        Write-Verbose "Executing 'Test-NetConnection -ComputerName $endpoint -Port 445'"

        $result = Test-NetConnection -ComputerName $endpoint -Port 445

        if ($result.TcpTestSucceeded -eq $False)
        {
            $message = "Unable to reach the storage account file endpoint." `
                + " To debug connectivity problems, please refer to the troubleshooting tool for Azure" `
                + " Files mounting errors on Windows, 'AzFileDiagnostics.ps1'" `
                + " (https://gallery.technet.microsoft.com/Troubleshooting-tool-for-a9fa1fe5)." `
                + " For possible solutions please refer to" `
                + " https://docs.microsoft.com/en-us/azure/storage/files/storage-troubleshoot-windows-file-connection-problems#cause-1-port-445-is-blocked"
            Write-Error -Message $message -ErrorAction Stop
        }
    }
}


function Debug-AzStorageAccountADObject
{
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName
    )

    process
    {
        #
        # Check if the object exists.
        #
    
        $azureStorageIdentity = Get-AzStorageAccountADObject -StorageAccountName $StorageAccountName `
            -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        #
        # Check if the object has the correct SPN (Service Principal Name)
        #

        $expectedSpnValue = Get-ServicePrincipalName -StorageAccountName $StorageAccountName `
            -ResourceGroupName $ResourceGroupName -ErrorAction Stop

        $properSpnSet = $azureStorageIdentity.ServicePrincipalNames.Contains($expectedSpnValue)

        if ($properSpnSet -eq $False) {
            $message = "The AD object $($azureStorageIdentity.Name) does not have the proper SPN" `
                + " of '$expectedSpnValue'. Please run the following command to repair the object in AD:" `
                + " 'Set-AD$($azureStorageIdentity.ObjectClass) -Identity $($azureStorageIdentity.Name) -ServicePrincipalNames @{Add=`"$expectedSpnValue`"}'"
            Write-Error -Message $message -ErrorAction Stop
        }
    }
}

function Get-OnPremAdUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$False, Position=0, HelpMessage="The user name or SID to look up the user")]
        [string]$Identity,

        [Parameter(Mandatory=$False, Position=1, HelpMessage="The domain name to look up the user")]
        [string]$Domain
    )
    process {
        if ([string]::IsNullOrEmpty($Identity)) {
            $Identity = $($env:UserName)
        }

        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = (Get-ADDomain).DnsRoot
        }

        Write-Verbose "Look up user $Identity in domain $Domain"

        $user = Get-ADUser -Identity $Identity -Server $Domain

        if ($null -eq $user) {
            $message = "User '$Identity' not found in domain '$Domain'. Please check" `
                + " whether the provided user identity or domain name is correct or not."
            Write-Error -Message $message -ErrorAction Stop
        }

        return $user
    }
}

function Get-OnPremAdUserGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$False, Position=0, HelpMessage="The user name or SID to look up the user groups")]
        [string]$Identity,

        [Parameter(Mandatory=$False, Position=1, HelpMessage="The domain name to look up the user groups")]
        [string]$Domain
    )
    process {
        if ([string]::IsNullOrEmpty($Identity)) {
            $Identity = $($env:UserName)
        }

        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = (Get-ADDomain).DnsRoot
        }

        Write-Verbose "Look up groups of user $Identity in domain $Domain"

        $groups = Get-ADPrincipalGroupMembership -Identity $Identity -Server $Domain

        if ($null -eq $groups) {
            $message = "Groups of use '$Identity' not found in domain '$Domain'. Please check" `
                + " whether the provided user identity or domain name is correct or not."
            Write-Error -Message $message -ErrorAction Stop
        }

        return $groups
    }
}

class CheckResult {
    [string]$Name
    [string]$Result
    [string]$Issue

    CheckResult(
        [string]$Name
    ) {
        $this.Name = $Name
        $this.Result = "Skipped"
        $this.Issue = ""
    }
}

function Debug-AzStorageAccountAuth {
    <#
    .SYNOPSIS
    Executes a sequence of checks to identify common problems with Azure Files Authentication issues.  
    
    .DESCRIPTION
    This cmdlet will query the client computer for Kerberos service tickets to Azure storage accounts.
    It will return an array of these objects, each object having a property 'Azure Files Health Status'
    which tells the health of the ticket.  It will error when there are no ticketsfound or if there are 
    unhealthy tickets found.
    .OUTPUTS
    Object[] of PSCustomObject containing klist ticket output.
    .EXAMPLE
    PS> Debug-AzStorageAccountAuth
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0, HelpMessage="Storage account name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$True, Position=1, HelpMessage="Resource group name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$False, Position=2, HelpMessage="Filter")]
        [string]$Filter,

        [Parameter(Mandatory=$False, Position=3, HelpMessage="Optional parameter for filter 'CheckSidHasAadUser' and 'CheckUserFileAccess'. The user name to check.")]
        [string]$UserName,

        [Parameter(Mandatory=$False, Position=4, HelpMessage="Optional parameter for filter 'CheckSidHasAadUser', 'CheckUserFileAccess' and 'CheckAadUserHasSid'. The domain name to look up the user.")]
        [string]$Domain,

        [Parameter(Mandatory=$False, Position=5, HelpMessage="Required parameter for filter 'CheckAadUserHasSid'. The Azure object ID or user principal name to check.")]
        [string]$ObjectId,

        [Parameter(Mandatory=$False, Position=6, HelpMessage="Required parameter for filter 'CheckUserFileAccess'. The SMB file path on the Azure file share mounted locally using storage account key.")]
        [string]$FilePath
    )

    process
    {
        $checksExecuted = 0;
        $filterIsPresent = ![string]::IsNullOrEmpty($Filter);
        $checks = @{
            "CheckPort445Connectivity" = [CheckResult]::new("CheckPort445Connectivity");
            "CheckDomainJoined" = [CheckResult]::new("CheckDomainJoined");
            "CheckADObject" = [CheckResult]::new("CheckADObject");
            "CheckGetKerberosTicket" = [CheckResult]::new("CheckGetKerberosTicket");
            "CheckADObjectPasswordIsCorrect" = [CheckResult]::new("CheckADObjectPasswordIsCorrect");
            "CheckSidHasAadUser" = [CheckResult]::new("CheckSidHasAadUser");
            "CheckAadUserHasSid" = [CheckResult]::new("CheckAadUserHasSid");
            "CheckStorageAccountDomainJoined" = [CheckResult]::new("CheckStorageAccountDomainJoined");
            "CheckUserRbacAssignment" = [CheckResult]::new("CheckUserRbacAssignment");
            "CheckUserFileAccess" = [CheckResult]::new("CheckUserFileAccess");
        }

        #
        # Port 445 check 
        #
        
        if (!$filterIsPresent -or $Filter -match "CheckPort445Connectivity")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckPort445Connectivity - START"

                Test-Port445Connectivity -StorageAccountName $StorageAccountName `
                    -ResourceGroupName $ResourceGroupName -ErrorAction Stop

                $checks["CheckPort445Connectivity"].Result = "Passed"
                Write-Verbose "CheckPort445Connectivity - SUCCESS"
            } catch {
                $checks["CheckPort445Connectivity"].Result = "Failed"
                $checks["CheckPort445Connectivity"].Issue = $_
                Write-Error "CheckPort445Connectivity - FAILED"
                Write-Error $_
            }
        }

        #
        # Domain-Joined Check
        #

        if (!$filterIsPresent -or $Filter -match "CheckDomainJoined")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckDomainJoined - START"
        
                if (!(Get-IsDomainJoined))
                {
                    $message = "Machine is not domain-joined. Mounting to Azure Files through" `
                        + " Active Directory Authentication is only supported when the computer is joined to" `
                        + " an Active Directory domain, which is synced to Azure AD with Azure AD Connect" `
                        + " (https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable#prerequisites)"
                    Write-Error -Message $message -ErrorAction Stop
                }

                $checks["CheckDomainJoined"].Result = "Passed"
                Write-Verbose "CheckDomainJoined - SUCCESS"
            } catch {
                $checks["CheckDomainJoined"].Result = "Failed"
                $checks["CheckDomainJoined"].Issue = $_
                Write-Error "CheckDomainJoined - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckADObject")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckADObject - START"

                Debug-AzStorageAccountADObject -StorageAccountName $StorageAccountName `
                    -ResourceGroupName $ResourceGroupName -ErrorAction Stop

                $checks["CheckADObject"].Result = "Passed"
                Write-Verbose "CheckADObject - SUCCESS"
            } catch {
                $checks["CheckADObject"].Result = "Failed"
                $checks["CheckADObject"].Issue = $_
                Write-Error "CheckADObject - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckGetKerberosTicket")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckGetKerberosTicket - START"

                Get-AzStorageKerberosTicketStatus -StorageaccountName $StorageAccountName `
                    -ResourceGroupName $ResourceGroupName -ErrorAction Stop

                $checks["CheckGetKerberosTicket"].Result = "Passed"
                Write-Verbose "CheckGetKerberosTicket - SUCCESS"
            } catch {
                $checks["CheckGetKerberosTicket"].Result = "Failed"
                $checks["CheckGetKerberosTicket"].Issue = $_
                Write-Error "CheckGetKerberosTicket - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckADObjectPasswordIsCorrect")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckADObjectPasswordIsCorrect - START"

                Test-AzStorageAccountADObjectPasswordIsKerbKey -StorageAccountName $StorageAccountName `
                    -ResourceGroupName $ResourceGroupName -ErrorIfNoMatch -ErrorAction Stop

                $checks["CheckADObjectPasswordIsCorrect"].Result = "Passed"
                Write-Verbose "CheckADObjectPasswordIsCorrect - SUCCESS"
            } catch {
                $checks["CheckADObjectPasswordIsCorrect"].Result = "Failed"
                $checks["CheckADObjectPasswordIsCorrect"].Issue = $_
                Write-Error "CheckADObjectPasswordIsCorrect - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckSidHasAadUser")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckSidHasAadUser - START"

                $currentUser = Get-OnPremAdUser -Identity $UserName -Domain $Domain -ErrorAction Stop

                Write-Verbose "User $UserName in domain $Domain has SID = $($currentUser.Sid)"

                $aadUser = Get-AadUserForSid $currentUser.Sid

                if ($null -eq $aadUser) {
                    $message = "Cannot find an AAD user with SID '$($currentUser.Sid) for" `
                        + " user $UserName' in domain '$Domain'. Please ensure the domain '$Domain' is" `
                        + " synced to Azure Active Directory using Azure AD Connect" `
                        + " (https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-roadmap)"
                    Write-Error -Message $message -ErrorAction Stop
                }

                Write-Verbose "Found AAD user '$($aadUser.UserPrincipalName)' for SID $($currentUser.Sid)"

                $checks["CheckSidHasAadUser"].Result = "Passed"
                Write-Verbose "CheckSidHasAadUser - SUCCESS"
            } catch {
                $checks["CheckSidHasAadUser"].Result = "Failed"
                $checks["CheckSidHasAadUser"].Issue = $_
                Write-Error "CheckSidHasAadUser - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckAadUserHasSid")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckAadUserHasSid - START"

                if ([string]::IsNullOrEmpty($ObjectId)) {
                    Write-Verbose -Message "Missing required parameter ObjectId for CheckAadUserHasSid requires ObjectId parameter to be present, skipping CheckAadUserHasSid"
                    $checks["CheckAadUserHasSid"].Result = "Skipped"
                }
                else {
                
                    if ([string]::IsNullOrEmpty($Domain)) {
                        $Domain = (Get-ADDomain).DnsRoot
                    }

                    Write-Verbose "CheckAadUserHasSid for object ID $ObjectId in domain $Domain"

                    $aadUser = Get-AzureADUser -ObjectId $ObjectId

                    if ($null -eq $aadUser) {
                        $message = "Cannot find an Azure AD user with ObjectId $ObjectId. Please check" `
                            + " whether the provided ObjecId is correct or not."
                        Write-Error -Message $message -ErrorAction Stop
                    }

                    if ([string]::IsNullOrEmpty($aadUser.OnPremisesSecurityIdentifier)) {
                        $message = "Azure AD user $ObjectId has no OnPremisesSecurityIdentifier. Please" `
                            + " ensure the domain '$Domain' is synced to Azure Active Directory using Azure AD Connect" `
                            + " (https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-roadmap)"
                        Write-Error -Message $message -ErrorAction Stop
                    }

                    $user = Get-ADUser -Identity $aadUser.OnPremisesSecurityIdentifier -Server $Domain

                    if ($null -eq $user) {
                        $message = "Azure AD user $ObjectId's SID $($aadUser.OnPremisesSecurityIdentifier)" `
                            + " is not found in domain $Domain. Please check whether the provided SID is correct."
                        Write-Error -Message $message -ErrorAction Stop
                    }

                    Write-Verbose "Azure AD user $ObjectId has SID $($aadUser.OnPremisesSecurityIdentifier) in domain $Domain"

                    $checks["CheckAadUserHasSid"].Result = "Passed"
                    Write-Verbose "CheckAadUserHasSid - SUCCESS"
                }

            } catch {
                $checks["CheckAadUserHasSid"].Result = "Failed"
                $checks["CheckAadUserHasSid"].Issue = $_
                Write-Error "CheckAadUserHasSid - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or ($Filter -match "CheckStorageAccountDomainJoined"))
        {
            try {
                $checksExecuted += 1
                Write-Verbose "CheckStorageAccountDomainJoined - START"

                $activeDirectoryProperties = Get-AzStorageAccountActiveDirectoryProperties `
                    -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop

                Write-Verbose -Message "Storage account $StorageAccountName is already joined in domain $($activeDirectoryProperties.DomainName)."
                
                $checks["CheckStorageAccountDomainJoined"].Result = "Passed"
                Write-Verbose "CheckStorageAccountDomainJoined - SUCCESS"
            } catch {
                $checks["CheckStorageAccountDomainJoined"].Result = "Failed"
                $checks["CheckStorageAccountDomainJoined"].Issue = $_
                Write-Error "CheckStorageAccountDomainJoined - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or ($Filter -match "CheckUserRbacAssignment")) {
            try {
                $checksExecuted += 1
                Write-Verbose "CheckUserRbacAssignment - START"

                Request-ConnectAzureAD

                $sidNames = @{}
                $user = Get-OnPremAdUser -Identity $UserName -Domain $Domain -ErrorAction Stop
                $sidNames[$user.SID.Value] = $user.DistinguishedName

                $groups = Get-OnPremAdUserGroups -Identity $user.SID -Domain $Domain -ErrorAction Stop
                $groups | ForEach-Object { $sidNames[$_.SID.Value] = $_.DistinguishedName }

                # The user needs following role assignments to have the share-level access.
                # Currently only three roles are defined, but new ones may be added in future,
                # hence use a prefix to check.
                # Storage File Data SMB Share Reader
                # Storage File Data SMB Share Contributor
                # Storage File Data SMB Share Elevated Contributor
                $smbRoleNamePrefix = "Storage File Data SMB Share"
                $smbRoleDefinitions = @{}
                Get-AzRoleDefinition | Where-Object { $_.Name.StartsWith($smbRoleNamePrefix) } `
                    | ForEach-Object { $smbRoleDefinitions[$_.Id] = $_ }
                
                $roleAssignments = Get-AzRoleAssignment -ResourceGroupName $ResourceGroupName `
                    -ResourceName $StorageAccountName -ResourceType Microsoft.Storage/storageAccounts `
                    | Where-Object { $smbRoleDefinitions.ContainsKey($_.RoleDefinitionId) }

                $roleDefinitions = @{}
                $assignedAdObjects = @{}

                foreach ($assignment in $roleAssignments) {
                    $aadObject = Get-AzureADObjectByObjectId -ObjectId $assignment.ObjectId

                    if (($null -ne $aadObject) `
                        -and (-not [string]::IsNullOrEmpty($aadObject.OnPremisesSecurityIdentifier)) `
                        -and ($sidNames.ContainsKey($aadObject.OnPremisesSecurityIdentifier))) {
                        if (-not $roleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                            $roleDefinitions[$assignment.RoleDefinitionId] = $smbRoleDefinitions[$assignment.RoleDefinitionId]
                        }

                        if (-not $assignedAdObjects.ContainsKey($assignment.RoleDefinitionId)) {
                            $assignedAdObjects[$assignment.RoleDefinitionId] = @()
                        }

                        $assignedAdObjects[$assignment.RoleDefinitionId] += $sidNames[$aadObject.OnPremisesSecurityIdentifier]
                    }
                }

                if ($roleDefinitions.Count -eq 0) {
                    $message = "User '$($user.UserPrincipalName)' is not assigned any SMB share-level permission to" `
                        + " storage account '$StorageAccountName' in resource group '$ResourceGroupName'. Please" `
                        + " configure proper share-level permission following the guidance at" `
                        + " https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-assign-permissions"
                    Write-Error -Message $message -ErrorAction Stop
                }

                Write-Host "------------------------------------------"
                Write-Host "User '$($user.UserPrincipalName)' is granted following SMB share-level permissions:"

                foreach ($roleDefinitionId in $roleDefinitions.Keys) {
                    Write-Host "Assigned role definition '$($roleDefinitions[$roleDefinitionId].Name)':"
                    $roleDefinitions[$roleDefinitionId]
                    Write-Host "AD objects being assigned with role definition '$($roleDefinitions[$roleDefinitionId].Name)':"
                    $assignedAdObjects[$roleDefinitionId] | Format-Table
                    Write-Host ""
                }

                Write-Host "------------------------------------------"

                $checks["CheckUserRbacAssignment"].Result = "Passed"
                Write-Verbose "CheckUserRbacAssignment - SUCCESS"
            } catch {
                $checks["CheckUserRbacAssignment"].Result = "Failed"
                $checks["CheckUserRbacAssignment"].Issue = $_
                Write-Error "CheckUserRbacAssignment - FAILED"
                Write-Error $_
            }
        }

        if (!$filterIsPresent -or $Filter -match "CheckUserFileAccess")
        {
            try {
                $checksExecuted += 1;
                Write-Verbose "CheckUserFileAccess - START"

                if ([string]::IsNullOrEmpty($FilePath)) {
                    Write-Verbose -Message "Missing required parameter FilePath for CheckUserFileAccess, skipping CheckUserFileAccess"
                    $checks["CheckUserFileAccess"].Result = "Skipped"
                } else {
                    $fileAcl = Get-Acl -Path $FilePath
                    if ($null -eq $fileAcl) {
                        $message = "Unable to get the ACL of '$FilePath'. Please check if the provided file path is correct."
                        Write-Error -Message $message -ErrorAction Stop
                    }

                    # Get the access rules explicitly assigned to and inherited by the file
                    $fileAccessRules = $fileAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                    if ($fileAccessRules.Count -eq 0) {
                        $message = "There is no access rule granted to '$FilePath'. Please consider setting up proper access rules" `
                            + " for the file (for example, using https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)"
                        Write-Error -Message $message -ErrorAction Stop
                    }
                
                    $user = Get-OnPremAdUser -Identity $UserName -Domain $Domain -ErrorAction Stop
                    Write-Verbose -Message "Found user '$($user.UserPrincipalName)' with SID '$($user.SID)'"

                    $identity = [System.Security.Principal.WindowsIdentity]::new($user.UserPrincipalName)

                    $sidRules = @{}
                    foreach ($accessRule in $fileAccessRules) {
                        if ($accessRule.IdentityReference -ieq $user.SID) {
                            if (-not $sidRules.ContainsKey($accessRule.IdentityReference)) {
                                $sidRules[$accessRule.IdentityReference] = @()
                            }

                            $sidRules[$accessRule.IdentityReference] += $accessRule
                        } else {
                            foreach ($group in $identity.Groups) {
                                if ($accessRule.IdentityReference -ieq $group.Value) {
                                    if (-not $sidRules.ContainsKey($accessRule.IdentityReference)) {
                                        $sidRules[$accessRule.IdentityReference] = @()
                                    }
        
                                    $sidRules[$accessRule.IdentityReference] += $accessRule                
                                }
                            }
                        }                        
                    }

                    if ($sidRules.Count -eq 0) {
                        $message = "User '$($user.UserPrincipalName)' is not assigned any permission to '$FilePath'." `
                            + " Please configure proper permission for the user to access the file (for example," `
                            + " using https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)"
                        Write-Error -Message $message -ErrorAction Stop
                    }
    
                    Write-Host "------------------------------------------"
                    Write-Host "User '$($user.UserPrincipalName)' is granted following permissions to '$FilePath':"
                    foreach ($sid in $sidRules.Keys) {
                        Write-Host "Granted access through SID $($sid):"
                        $sidRules[$sid]
                    }

                    Write-Host "------------------------------------------"

                    $checks["CheckUserFileAccess"].Result = "Passed"
                    Write-Verbose "CheckUserFileAccess - SUCCESS"
                }

            } catch {
                $checks["CheckUserFileAccess"].Result = "Failed"
                $checks["CheckUserFileAccess"].Issue = $_
                Write-Error "CheckUserFileAccess - FAILED"
                Write-Error $_
            }
        }

        if ($filterIsPresent -and $checksExecuted -eq 0)
        {
            $message = "Filter '$Filter' provided does not match any options. No checks were executed." `
                + " Available filters are {$($checks.Keys -join ', ')}"
            Write-Error -Message $message -ErrorAction Stop
        }
        else
        {
            Write-Host "Summary of checks:"
            $checks.Values | Format-Table -Property Name,Result
            
            $issues = $checks.Values | Where-Object { $_.Result -ieq "Failed" }

            if ($issues.Length -gt 0) {
                Write-Host "Issues found:"
                $issues | ForEach-Object { Write-Host -ForegroundColor Red "---- $($_.Name) ----`n$($_.Issue)" }
            }
        }
    }
}


function Set-StorageAccountDomainProperties {
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
        PS C:\> Set-StorageAccountDomainProperties -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup" -ADObjectName "adObjectName" -Domain "domain" -Force
    .EXAMPLE
        PS C:\> Set-StorageAccountDomainProperties -StorageAccountName "storageAccount" -ResourceGroupName "resourceGroup" -DisableADDS
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1)]
        [string]$StorageAccountName,

        [Parameter(Mandatory=$false, Position=2)]
        [string]$ADObjectName,

        [Parameter(Mandatory=$false, Position=3)]
        [string]$Domain,

        [Parameter(Mandatory=$false, Position=4)]
        [switch]$DisableADDS,

        [Parameter(Mandatory=$false, Position=5)]
        [switch]$Force
    )

    if ($DisableADDS) {
        Write-Verbose "Setting AD properties on $StorageAccountName in $ResourceGroupName : `
            EnableActiveDirectoryDomainServicesForFile=$false"

        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName `
            -EnableActiveDirectoryDomainServicesForFile $false
    } else {

        $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName

        if (($null -ne $storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties) -and (-not $Force)) {
            Write-Error "ActiveDirectoryDomainService is already enabled on storage account $StorageAccountName in resource group $($ResourceGroupName): `
                DomainName=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainName) `
                NetBiosDomainName=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.NetBiosDomainName) `
                ForestName=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.ForestName) `
                DomainGuid=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainGuid) `
                DomainSid=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainSid) `
                AzureStorageSid=$($storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.AzureStorageSid)" `
                -ErrorAction Stop
        }

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
            -ADObjectName $ADObjectName `
            -Domain $Domain `
            -ErrorAction Stop
        $azureStorageSid = $azureStorageIdentity.SID.Value

        $domainGuid = $domainInformation.ObjectGUID.ToString()
        $domainName = $domainInformation.DnsRoot
        $domainSid = $domainInformation.DomainSID.Value
        $forestName = $domainInformation.Forest
        $netBiosDomainName = $domainInformation.DnsRoot

        Write-Verbose "Setting AD properties on $StorageAccountName in $ResourceGroupName : `
            EnableActiveDirectoryDomainServicesForFile=$true, ActiveDirectoryDomainName=$domainName, `
            ActiveDirectoryNetBiosDomainName=$netBiosDomainName, ActiveDirectoryForestName=$($domainInformation.Forest) `
            ActiveDirectoryDomainGuid=$domainGuid, ActiveDirectoryDomainSid=$domainSid, `
            ActiveDirectoryAzureStorageSid=$azureStorageSid"

        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName `
             -EnableActiveDirectoryDomainServicesForFile $true -ActiveDirectoryDomainName $domainName `
             -ActiveDirectoryNetBiosDomainName $netBiosDomainName -ActiveDirectoryForestName $forestName `
             -ActiveDirectoryDomainGuid $domainGuid -ActiveDirectoryDomainSid $domainSid `
             -ActiveDirectoryAzureStorageSid $azureStorageSid
    }

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
         [Microsoft.Azure.Commands.Management.Storage.Models.PSStorageAccount]$StorageAccount,

         [Parameter(Mandatory=$false)]
         [switch]$ErrorIfNoMatch = $false
    )

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process
    {
        switch ($PSCmdlet.ParameterSetName) {
            "StorageAccountName" {
                $StorageAccount = Validate-StorageAccount -ResourceGroupName $ResourceGroupName `
                    -StorageAccountName $StorageAccountName -ErrorAction Stop
            }

            "StorageAccount" {                
                $ResourceGroupName = $StorageAccount.ResourceGroupName
                $StorageAccountName = $StorageAccount.StorageAccountName
            }

            default {
                throw [ArgumentException]::new("Unrecognized parameter set $_")
            }
        }

        $kerbKeys = Get-AzStorageAccountKerbKeys -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $StorageAccountName -ErrorAction Stop

        $adObj = Get-AzStorageAccountADObject -StorageAccount $StorageAccount -ErrorAction Stop

        $activeDirectoryProperties = Get-AzStorageAccountActiveDirectoryProperties `
            -StorageAccount $StorageAccount -ErrorAction Stop

        $domainDns = $activeDirectoryProperties.DomainName
        $domain = Get-ADDomain -Server $domainDns

        $userName = $domain.Name + "\" + $adObj.Name

        $oneKeyMatches = $false
        $keyMatches = [KerbKeyMatch[]]@()
        foreach ($key in $kerbKeys) {
            if ($null -ne (New-Object Directoryservices.DirectoryEntry "", $userName, $key.Value).PsBase.Name) {
                Write-Verbose "Found that $($key.KeyName) matches password for $StorageAccountName in AD."
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
            $message = "Password for $userName does not match kerb1 or kerb2 of" `
                + " storage account: $StorageAccountName. Please run the following command to" `
                + " resync the AD password with the kerb key of the storage account and retry:" `
                + " Update-AzStorageAccountADObjectPassword." `
                + " (https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-update-password)"
            
            if ($ErrorIfNoMatch) {
                Write-Error -Message $message -ErrorAction Stop
            } else {
                Write-Warning -Message $message
            }
        }

        return $keyMatches
    }
}

function Update-AzStorageAccountADObjectPassword {
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
        $domain = $storageAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainName

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
                $kerbKeys = Get-AzStorageAccountKerbKeys `
                    -ResourceGroupName $StorageAccount.ResourceGroupName `
                    -StorageAccountName $StorageAccount.StorageAccountName `
                    -ErrorAction Stop
            }             
        
            $kerbKey = $kerbKeys | `
                Where-Object { $_.KeyName -eq $RotateToKerbKey } | `
                Select-Object -ExpandProperty Value  
    
            # $otherKerbKey = $kerbKeys | `
            #     Where-Object { $_.KeyName -eq $otherKerbKeyName } | `
            #     Select-Object -ExpandProperty Value
    
            # $oldPassword = ConvertTo-SecureString -String $otherKerbKey -AsPlainText -Force
            $newPassword = ConvertTo-SecureString -String $kerbKey -AsPlainText -Force
    
            # if ($Force.ToBool()) {
                Write-Verbose -Message ("Attempt reset on " + $adObj.SamAccountName + " to $RotateToKerbKey")
                Set-ADAccountPassword `
                    -Identity $adObj `
                    -Reset `
                    -NewPassword $newPassword `
                    -Server $domain `
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

function Update-AzStorageAccountAuthForAES256 {
    <#
    .SYNOPSIS 
    Update a storage account to support AES256 encryption.
    .DESCRIPTION
    This cmdlet will check and rejoin the storage account to an Active Directory domain with AES256 support.
    .PARAMETER ResourceGroupName
    The name of the resource group containing the storage account you would like to update. If StorageAccount is specified, 
    this parameter should not specified.
    .PARAMETER StorageAccountName
    The name of the storage account you would like to update. If StorageAccount is specified, this parameter 
    should not be specified.
    .PARAMETER StorageAccount
    A storage account object you would like to update. If StorageAccountName and ResourceGroupName is specified, this 
    parameter should not specified.
    .EXAMPLE
    PS> Update-AzStorageAccountAuthForAES256 -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount"
    .EXAMPLE 
    PS> $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "myStorageAccount"
    PS> Update-AzStorageAccountAuthForAES256 -StorageAccount $storageAccount
    .EXAMPLE
    PS> Get-AzStorageAccount -ResourceGroupName "myResourceGroup" | Update-AzStorageAccountAuthForAES256
    In this example, note that a specific storage account has not been specified to 
    Get-AzStorageAccount. This means Get-AzStorageAccount will pipe every storage account 
    in the resource group myResourceGroup to Update-AzStorageAccountAuthForAES256.
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
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
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "StorageAccount") {
            $StorageAccountName = $StorageAccount.StorageAccountName
            $ResourceGroupName = $StorageAccount.ResourceGroupName
        }

        $adObject = Get-AzStorageAccountADObject -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $StorageAccountName -ErrorAction Stop

        $activeDirectoryProperties = Get-AzStorageAccountActiveDirectoryProperties `
            -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
        $domain = $activeDirectoryProperties.DomainName

        if (($adObject.ObjectClass -ine "computer") -or ($adObject.SamAccountName.TrimEnd("$") -ine $StorageAccountName)) {
            $message = "Removing object '$($adObject.DistinguishedName)' of type '$adObject.ObjectClass' from domain '$domain'." `
                + " AES256 is only supported for computer objects."
            Write-Verbose -Message $message

            Remove-ADObject -Identity $adObject.DistinguishedName -Server $domain -Confirm:$false -ErrorAction Stop

            $organizationalUnitDistinguishedName = $adObject.DistinguishedName.Substring($adObject.DistinguishedName.IndexOf(',') + 1)

            $message = "Join storage account '$StorageAccountName' to domain '$domain'" `
                + " as a computer object under '$organizationalUnitDistinguishedName'"
            Write-Verbose -Message $message

            Join-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName `
                -Domain $domain -DomainAccountType "ComputerAccount" `
                -OrganizationalUnitDistinguishedName $organizationalUnitDistinguishedName `
                -ADObjectNameOverride $StorageAccountName -ErrorAction Stop
            
            $adObject = Get-AzStorageAccountADObject -ResourceGroupName $ResourceGroupName `
                -StorageAccountName $StorageAccountName -ErrorAction Stop
        }
        
        Write-Verbose -Message "Set AD object '$($adObject.DistinguishedName)' to use AES256 for Kerberos authentication"
        Set-ADComputer -Identity $adObject.DistinguishedName -Server $domain `
            -KerberosEncryptionType "AES256" -ErrorAction Stop

        Update-AzStorageAccountADObjectPassword -ResourceGroupname $ResourceGroupName -StorageAccountName $StorageAccountName `
            -RotateToKerbKey kerb2 -ErrorAction Stop
    }
}

function Join-AzStorageAccount {
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
    .PARAMETER OrganizationalUnitDistinguishedName
    The distinguished name of the organizational unit (i.e. "OU=Workstations,DC=contoso,DC=com"). This parameter is optional, but many environments will require it.
    .PARAMETER ADObjectNameOverride
    By default, the AD object that is created will have a name to match the storage account. This parameter overrides that to an
    arbitrary name. This does not affect how you access your storage account.
    .PARAMETER OverwriteExistingADObject
    The switch to indicate whether to overwrite the existing AD object for the storage account. Default is $false and the script
    will stop if find an existing AD object for the storage account.
    .PARAMETER EncryptionType
    The type of encryption algorithm for the Kerberos ticket. Default is "'RC4','AES256'" which supports both 'RC4' and 'AES256' encryptions.
    .EXAMPLE
    PS> Join-AzStorageAccount -ResourceGroupName "myResourceGroup" -StorageAccountName "myStorageAccount" -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"
    .EXAMPLE 
    PS> $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "myStorageAccount"
    PS> Join-AzStorageAccount -StorageAccount $storageAccount -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"
    .EXAMPLE
    PS> Get-AzStorageAccount -ResourceGroupName "myResourceGroup" | Join-AzStorageAccount -Domain "subsidiary.corp.contoso.com" -DomainAccountType ComputerAccount -OrganizationalUnitName "StorageAccountsOU"
    In this example, note that a specific storage account has not been specified to 
    Get-AzStorageAccount. This means Get-AzStorageAccount will pipe every storage account 
    in the resource group myResourceGroup to Join-AzStorageAccount.
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
        [string]$DomainAccountType = "ComputerAccount",

        [Parameter(Mandatory=$false, Position=4)]
        [Alias('OrganizationUnitName')]
        [string]$OrganizationalUnitName,

        [Parameter(Mandatory=$false, Position=5)]
        [Alias('OrganizationUnitDistinguishedName')]
        [string]$OrganizationalUnitDistinguishedName,

        [Parameter(Mandatory=$false, Position=5)]
        [string]$ADObjectNameOverride,

        [Parameter(Mandatory=$false, Position=6)]
        [switch]$OverwriteExistingADObject,

        [Parameter(Mandatory=$false, Position=7)]
        [System.Collections.Generic.HashSet[string]]$EncryptionType = @("RC4","AES256")
    ) 

    begin {
        Assert-IsWindows
        Assert-IsDomainJoined
        Request-ADFeature
    }

    process {
        # The proper way to do this is with a parameter set, but the parameter sets are not being generated correctly.
        if (
            $PSBoundParameters.ContainsKey("OrganizationalUnitName") -and 
            $PSBoundParameters.ContainsKey("OrganizationalUnitDistinguishedName")
        ) {
            Write-Error `
                    -Message "Only one of OrganizationalUnitName and OrganizationalUnitDistinguishedName should be specified." `
                    -ErrorAction Stop
        }

        if (($DomainAccountType -ieq "ServiceLogonAccount") -and ($EncryptionType -contains "AES256")) {
            $message = "Parameter -DomainAccountType is 'ServiceLogonAccount'," `
                + " which will not be supported AES256 encryption for Kerberos tickets."
            Write-Warning -Message $message
        }

        if ($PSCmdlet.ParameterSetName -eq "StorageAccount") {
            $StorageAccountName = $StorageAccount.StorageAccountName
            $ResourceGroupName = $StorageAccount.ResourceGroupName
        }
        
        if ($EncryptionType -contains "AES256") {
            if ($PSBoundParameters.ContainsKey("ADObjectNameOverride") -and ($ADObjectNameOverride -ine $StorageAccountName)) {
                $message = "Parameter -ADObjectNameOverride '$ADObjectNameOverride' is different from storage account" `
                    + " name '$StorageAccountName'. It cannot be used as the SamAccountName to create an Active Directory object" `
                    + " for the storage account. Azure Files will be supporting AES256 encryption for Kerberos tickets," `
                    + " which requires that the SamAccountName match the storage account name."
                Write-Error -Message $message -ErrorAction Stop
            }
            if ($StorageAccountName.Length -gt 15) {
                $message = "Parameter -StorageAccountName '$StorageAccountName' has more than 15 characters," `
                    + " which is not supported to be used as the SamAccountName to create an Active Directory object" `
                    + " for the storage account. Azure Files will be supporting AES256 encryption for Kerberos tickets," `
                    + " which requires that the SamAccountName match the storage account name. Please consider using" `
                    + " a storage account with a shorter name."
                Write-Error -Message $message -ErrorAction Stop
            }
        }

        if (!$PSBoundParameters.ContainsKey("ADObjectNameOverride")) {
            if ($StorageAccountName.Length -gt 15) {
                $randomSuffix = Get-RandomString -StringLength 5 -AlphanumericOnly
                $ADObjectNameOverride = $StorageAccountName.Substring(0, 10) + $randomSuffix
            } else {
                $ADObjectNameOverride = $StorageAccountName
            }
        }
        
        Write-Verbose -Message "Using $ADObjectNameOverride as the name for the ADObject."

        $caption = "Domain join $StorageAccountName"
        $verboseConfirmMessage = ("This action will domain join the requested storage account to the requested domain.")
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            # Ensure the storage account exists.
            if ($PSCmdlet.ParameterSetName -eq "StorageAccountName") {
                $StorageAccount = Validate-StorageAccount `
                    -ResourceGroupName $ResourceGroupName `
                    -StorageAccountName $StorageAccountName `
                    -ErrorAction Stop
            }

            # Ensure the storage account has a "kerb1" key.
            Ensure-KerbKeyExists -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop

            # Create the service account object for the storage account.
            $newParams = @{
                "ADObjectName" = $ADObjectNameOverride;
                "StorageAccountName" = $StorageAccountName;
                "ResourceGroupName" = $ResourceGroupName;
                "ObjectType" = $DomainAccountType
            }

            if ($PSBoundParameters.ContainsKey("Domain")) {
                $newParams += @{ "Domain" = $Domain }
            }

            if ($PSBoundParameters.ContainsKey("OrganizationalUnitName")) {
                $newParams += @{ "OrganizationalUnit" = $OrganizationalUnitName }
            }

            if ($PSBoundParameters.ContainsKey("OrganizationalUnitDistinguishedName")) {
                $newParams += @{ "OrganizationalUnitDistinguishedName" = $OrganizationalUnitDistinguishedName }
            }

            if ($PSBoundParameters.ContainsKey("OverwriteExistingADObject")) {
                $newParams += @{ "OverwriteExistingADObject" = $OverwriteExistingADObject }
            }

            $ADObjectNameOverride = New-ADAccountForStorageAccount @newParams -ErrorAction Stop

            Write-Verbose "Created AD object $ADObjectNameOverride"

            # Set domain properties on the storage account.
            Set-StorageAccountDomainProperties `
                -ADObjectName $ADObjectNameOverride `
                -ResourceGroupName $ResourceGroupName `
                -StorageAccountName $StorageAccountName `
                -Domain $Domain `
                -Force
        }
    }
}

# Add alias for Join-AzStorageAccountForAuth
New-Alias -Name "Join-AzStorageAccountForAuth" -Value "Join-AzStorageAccount"

function Get-ADDnsRootFromDistinguishedName {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern("^(CN=([a-z]|[0-9]|[ .])+)((,OU=([a-z]|[0-9]|[ .])+)*)((,DC=([a-z]|[0-9]|[ .])+)+)$")]
        [string]$DistinguishedName
    )

    process {
        $dcPath = $DistinguishedName.Split(",") | `
            Where-Object { $_.Substring(0, 2) -eq "DC" } | `
            ForEach-Object { $_.Substring(3, $_.Length - 3) }

        $sb = [System.Text.StringBuilder]::new()

        for($i = 0; $i -lt $dcPath.Length; $i++) {
            if ($i -gt 0) {
                $sb.Append(".") | Out-Null
            }

            $sb.Append($dcPath[$i])
        }

        return $sb.ToString()
    }
}
#endregion

#region General Azure cmdlets
function Expand-AzResourceId {
    <#
    .SYNOPSIS
    Breakdown an ARM id by parts.
    .DESCRIPTION
    This cmdlet breaks down an ARM id by its parts, to make it easy to use the components as inputs in cmdlets/scripts.
    .PARAMETER ResourceId
    The resource identifier to be broken down.
    .EXAMPLE
    $idParts = Get-AzStorageAccount `
            -ResourceGroupName "myResourceGroup" `
            -StorageAccountName "mystorageaccount123" | `
        Expand-AzResourceId
    # Get the subscription 
    $subscription = $idParts.subscriptions
    # Do something else interesting as desired.
    .OUTPUTS
    System.Collections.Specialized.OrderedDictionary
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$true, 
            Position=0, 
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)]
        [Alias("Scope", "Id")]
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
    <#
    .SYNOPSIS
    Recombine an expanded ARM id into a single string which can be used by Az cmdlets.
    .DESCRIPTION
    This cmdlet takes the output of the cmdlet Expand-AzResourceId and puts it back into a single string identifier. Note, this cmdlet does not currently validate that components are valid in an ARM template, so use with care.
    .PARAMETER ExpandedResourceId
    An OrderedDictionary representing an expanded ARM identifier.
    .EXAMPLE
    $fileShareId = Get-AzRmStorageShare `
            -ResourceGroupName "myResourceGroup" `
            -StorageAccountName "mystorageaccount123" `
            -Name "testshare" | `
        Expand-AzResourceId
    
    $fileShareId.Remove("shares")
    $fileShareId.Remove("fileServices")
    $storageAccountId = $fileShareId | Compress-AzResourceId
    .OUTPUTS
    System.String
    #>

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
    <#
    .SYNOPSIS
    Connect to an Azure AD tenant using the AzureAD cmdlets.
    .DESCRIPTION
    Correctly import the AzureAD module for your PowerShell version and then sign in using the same tenant is the currently signed in Az user. This wrapper is necessary as 1. AzureAD is not directly compatible with PowerShell 6 (though this can be achieved through the WindowsCompatibility module), and 2. AzureAD doesn't necessarily log you into the same tenant as the Az cmdlets according to their documentation (although it's not clear when it doesn't).
    .EXAMPLE
    Request-ConnectAzureAD
    #>

    [CmdletBinding()]
    param()

    Assert-IsWindows
    Request-AzureADModule

    $aadModule = Get-Module | Where-Object { $_.Name -like "AzureAD" }
    if ($null -eq $aadModule) {
        if ($PSVersionTable.PSVersion -ge [Version]::new(6,0,0,0)) {
            Import-WinModule -Name AzureAD -Verbose:$false
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
    <#
    .SYNOPSIS
    Get the Azure AD domains associated with this Azure AD tenant.
    .DESCRIPTION
    This cmdlet is a wrapper around Get-AzureADDomain that is provided to future proof for adding cross-platform support, as AzureAD is not a cross-platform PowerShell module.
    .PARAMETER Name
    Specifies the name of a domain.
    .EXAMPLE
    $domains = Get-AzureADDomainInternal
    .EXAMPLE
    $specificDomain = Get-AzureADDomainInternal -Name "contoso.com"
    .OUTPUTS
    Microsoft.Open.AzureAD.Model.Domain
    Deserialized.Microsoft.Open.AzureAD.Model.Domain, if accessed through the WindowsCompatibility module
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Name
    )

    begin {
        Assert-IsWindows
        Request-ConnectAzureAD
    }

    process {
        $getParams = @{}
        if ($PSBoundParameters.ContainsKey("Name")) {
            $getParams += @{ "Name" = $Name}
        }

        return (Get-AzureADDomain @Name)
    }
}

function Get-AzCurrentAzureADUser {
    <#
    .SYNOPSIS
    Get the name of the Azure AD user logged into Az PowerShell.
    .DESCRIPTION
    In general, Get-AzContext provides the logged in username of the user using Az module, however, for accounts that are not part of the Azure AD domain (ex. like a MSA used to create an Azure subscription), this will not match the Azure AD identity, which will be of the format: externalemail_outlook.com#EXT#@contoso.com. This cmdlet returns the correct user as defined in Azure AD.
    .EXAMPLE
    $currentUser = Get-AzCurrentAzureADUser
    .OUTPUTS
    System.String
    #>

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
$OperationCache = [Dictionary[string, object[]]]::new()
function Test-AzPermission {
    <#
    .SYNOPSIS
    Test specific permissions required for a given user.
    .DESCRIPTION
    Since customers can defined custom roles for their Azure users, checking permissions isn't as easy as simply looking at the predefined roles. Additionally, users may be in multiple roles that confer (or remove) the ability to do specific things on an Azure resource. This cmdlet takes a list of specific operations and ensures that the user, current or specified, has the specified permissions on the scope (subscription, resource group, or resource).
    .EXAMPLE
    # Does the current user have the ability to list storage account keys?
    $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "csostoracct"
    $storageAccount | Test-AzPermission -OperationName "Microsoft.Storage/storageAccounts/listkeys/action"
    .EXAMPLE
    # Does this specific user have the ability to list storage account keys
    $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "csostoracct"
    $storageAccount | Test-AzPermission `
            -OperationName "Microsoft.Storage/storageAccounts/listkeys/action" `
            -SignInName "user@contoso.com"
    .OUTPUTS
    System.Collections.Generic.Dictionary<string, bool>
    #>

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

    process {
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
    <#
    .SYNOPSIS
    Check if the user has the required permissions and throw an error if they don't.
    .DESCRIPTION
    This cmdlet wraps Test-AzPermission and throws an error if the user does not have the required permissions. This cmdlet is meant for use in cmdlets or scripts.
    .EXAMPLE
    $storageAccount = Get-AzStorageAccount -ResourceGroupName "myResourceGroup" -Name "mystorageaccount123"
    $storageAccount | Assert-AzPermission -OperationName "Microsoft.Storage/storageAccounts/listkeys/action"
    # Errors will be thrown if the user does not have this permission.
    #>

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

        $testParams += @{
            "Scope" = $Scope
        }

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
        $falseValues = $permissionMatches.GetEnumerator() | Where-Object { $_.Value -eq $false }
        if ($null -ne $falseValues) {
            $errorBuilder = [StringBuilder]::new()
            $errorBuilder.Append("The current user lacks the following permissions: ") | Out-Null
            for($i=0; $i -lt $falseValues.Length; $i++) {
                if ($i -gt 0) {
                    $errorBuilder.Append(", ") | Out-Null
                }

                $errorBuilder.Append($falseValues[$i].Key) | Out-Null
            }

            $errorBuilder.Append(".") | Out-Null
            Write-Error -Message $errorBuilder.ToString() -ErrorAction Stop
        }
    }
}
#endregion

#region DNS cmdlets
class DnsForwardingRule {
    [string]$DomainName
    [bool]$AzureResource
    [ISet[string]]$MasterServers

    hidden Init(
        [string]$domainName, 
        [bool]$azureResource, 
        [ISet[string]]$masterServers
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = $masterServers
    }

    hidden Init(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable[string]]$masterServers 
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = [HashSet[string]]::new($masterServers)
    }

    hidden Init(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable]$masterServers
    ) {
        $this.DomainName = $domainName
        $this.AzureResource = $azureResource
        $this.MasterServers = [HashSet[string]]::new()

        foreach($item in $masterServers) {
            $this.MasterServers.Add($item.ToString()) | Out-Null
        }
    }

    DnsForwardingRule(
        [string]$domainName, 
        [bool]$azureResource, 
        [ISet[string]]$masterServers
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable[string]]$masterServers 
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule(
        [string]$domainName,
        [bool]$azureResource,
        [IEnumerable]$masterServers
    ) {
        $this.Init($domainName, $azureResource, $masterServers)
    }

    DnsForwardingRule([PSCustomObject]$customObject) {
        $properties = $customObject | `
            Get-Member | `
            Where-Object { $_.MemberType -eq "NoteProperty" }

        $hasDomainName = $properties | `
            Where-Object { $_.Name -eq "DomainName" }
        if ($null -eq $hasDomainName) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the DomainName property.", "customObject")
        }
        
        $hasAzureResource = $properties | `
            Where-Object { $_.Name -eq "AzureResource" }
        if ($null -eq $hasAzureResource) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the AzureResource property.", "customObject")
        }

        $hasMasterServers = $properties | `
            Where-Object { $_.Name -eq "MasterServers" }
        if ($null -eq $hasMasterServers) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the MasterServers property.", "customObject")
        }

        if ($customObject.MasterServers -isnot [object[]]) {
            throw [ArgumentException]::new(
                "Deserialized MasterServers is not an array.", "customObject")
        }

        $this.Init(
            $customObject.DomainName, 
            $customObject.AzureResource, 
            $customObject.MasterServers)
    }

    [int] GetHashCode() {
        return $this.DomainName.GetHashCode()
    }

    [bool] Equals([object]$obj) {
        return $obj.GetHashCode() -eq $this.GetHashCode()
    }
}

class DnsForwardingRuleSet {
    [ISet[DnsForwardingRule]]$DnsForwardingRules

    DnsForwardingRuleSet() {
        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()
    }

    DnsForwardingRuleSet([IEnumerable]$dnsForwardingRules) {
        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()

        foreach($rule in $dnsForwardingRules) {
            $this.DnsForwardingRules.Add($rule) | Out-Null
        }
    }

    DnsForwardingRuleSet([PSCustomObject]$customObject) {
        $properties = $customObject | `
            Get-Member | `
            Where-Object { $_.MemberType -eq "NoteProperty" }
        
        $hasDnsForwardingRules = $properties | `
            Where-Object { $_.Name -eq "DnsForwardingRules" }
        if ($null -eq $hasDnsForwardingRules) {
            throw [ArgumentException]::new(
                "Deserialized customObject does not have the DnsForwardingRules property.", "customObject")
        }

        if ($customObject.DnsForwardingRules -isnot [object[]]) {
            throw [ArgumentException]::new(
                "Deserialized DnsForwardingRules is not an array.", "customObject")
        }

        $this.DnsForwardingRules = [HashSet[DnsForwardingRule]]::new()
        foreach($rule in $customObject.DnsForwardingRules) {
            $this.DnsForwardingRules.Add([DnsForwardingRule]::new($rule)) | Out-Null
        }
    }
}

function Add-AzDnsForwardingRule {
    [CmdletBinding()]
    
    param(
        [Parameter(
            Mandatory=$true, 
            ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyCollection()]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true, ParameterSetName="AzureEndpointParameterSet")]
        [ValidateSet(
            "StorageAccountEndpoint", 
            "SqlDatabaseEndpoint", 
            "KeyVaultEndpoint")]
        [string]$AzureEndpoint,
        
        [Parameter(Mandatory=$true, ParameterSetName="ManualParameterSet")]
        [string]$DomainName,
        
        [Parameter(Mandatory=$false, ParameterSetName="ManualParameterSet")]
        [switch]$AzureResource,

        [Parameter(Mandatory=$true, ParameterSetName="ManualParameterSet")]
        [System.Collections.Generic.HashSet[string]]$MasterServers,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "Overwrite",
            "Merge",
            "Disallow"
        )]
        [string]$ConflictBehavior = "Overwrite"
    )
    
    process {
        $forwardingRules = $DnsForwardingRuleSet.DnsForwardingRules

        if ($PSCmdlet.ParameterSetName -eq "AzureEndpointParameterSet") {
            $subscriptionContext = Get-AzContext
            if ($null -eq $subscriptionContext) {
                throw [AzureLoginRequiredException]::new()
            }
            $environmentEndpoints = Get-AzEnvironment -Name $subscriptionContext.Environment

            switch($AzureEndpoint) {
                "StorageAccountEndpoint" {
                    $DomainName = $environmentEndpoints.StorageEndpointSuffix
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }

                "SqlDatabaseEndpoint" {
                    $reconstructedEndpoint = [string]::Join(".", (
                        $environmentEndpoints.SqlDatabaseDnsSuffix.Split(".") | Where-Object { ![string]::IsNullOrEmpty($_) }))
                    
                    $DomainName = $reconstructedEndpoint
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }

                "KeyVaultEndpoint" {
                    $DomainName = $environmentEndpoints.AzureKeyVaultDnsSuffix
                    $AzureResource = $true

                    $MasterServers = [System.Collections.Generic.HashSet[string]]::new()
                    $MasterServers.Add($azurePrivateDnsIp) | Out-Null
                }
            }
        }

        $forwardingRule = [DnsForwardingRule]::new($DomainName, $AzureResource, $MasterServers)
        $conflictRule = [DnsForwardingRule]$null

        if ($forwardingRules.TryGetValue($forwardingRule, [ref]$conflictRule)) {
            switch($ConflictBehavior) {
                "Overwrite" {
                    $forwardingRules.Remove($conflictRule) | Out-Null
                    $forwardingRules.Add($forwardingRule) | Out-Null
                }

                "Merge" {
                    if ($forwardingRule.AzureResource -ne $conflictRule.AzureResource) {
                        throw [System.ArgumentException]::new(
                            "Azure resource status does not match for domain name $domain.", "AzureResource")
                    }

                    foreach($newMasterServer in $forwardingRule.MasterServers) {
                        $conflictRule.MasterServers.Add($newMasterServer) | Out-Null
                    }
                }

                "Disallow" {
                    throw [System.ArgumentException]::new(
                        "Domain name $domainName already exists in ruleset.", "DnsForwardingRules") 
                }
            }
        } else {
            $forwardingRules.Add($forwardingRule) | Out-Null
        }

        return $DnsForwardingRuleSet
    }
}

function New-AzDnsForwardingRuleSet {
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet(
            "StorageAccountEndpoint", 
            "SqlDatabaseEndpoint", 
            "KeyVaultEndpoint")]
        [System.Collections.Generic.HashSet[string]]$AzureEndpoints,

        [Parameter(Mandatory=$false)]
        [switch]$SkipOnPremisesDns,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$OnPremDnsHostNames,

        [Parameter(Mandatory=$false)]
        [string]$OnPremDomainName,

        [Parameter(Mandatory=$false)]
        [switch]$SkipParentDomain
    )

    Request-ADFeature

    $ruleSet = [DnsForwardingRuleSet]::new()
    foreach($azureEndpoint in $AzureEndpoints) {
        Add-AzDnsForwardingRule -DnsForwardingRuleSet $ruleSet -AzureEndpoint $azureEndpoint | Out-Null
    }

    if (!$SkipOnPremisesDns) {
        if ([string]::IsNullOrEmpty($OnPremDomainName)) {
            $domain = Get-ADDomainInternal
        } else {
            $domain = Get-ADDomainInternal -Identity $OnPremDomainName
        }

        if (!$SkipParentDomain) {
            while($null -ne $domain.ParentDomain) {
                $domain = Get-ADDomainInternal -Identity $domain.ParentDomain
            }
        }

        if ($null -eq $OnPremDnsHostNames) {
            $onPremDnsServers = Resolve-DnsNameInternal -Name $domain.DNSRoot | `
                Where-Object { $_.Type -eq "A" } | `
                Select-Object -ExpandProperty IPAddress
        } else {
            $onPremDnsServers = $OnPremDnsHostNames | `
                Resolve-DnsNameInternal | `
                Where-Object { $_.Type -eq "A" } | `
                Select-Object -ExpandProperty IPAddress
        }

        Add-AzDnsForwardingRule `
                -DnsForwardingRuleSet $ruleSet `
                -DomainName $domain.DNSRoot `
                -MasterServers $OnPremDnsServers | `
            Out-Null
    }

    return $ruleSet
}

function Clear-DnsClientCacheInternal {
    switch((Get-OSPlatform)) {
        "Windows" {
            Clear-DnsClientCache
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

function Push-DnsServerConfiguration {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]

    param(
        [Parameter(Mandatory=$true, ParameterSetName="AzDnsServer")]
        [Parameter(Mandatory=$true, ParameterSetName="OnPremDnsServer")]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$false, ParameterSetName="AzDnsServer")]
        [Parameter(Mandatory=$false, ParameterSetName="OnPremDnsServer")]
        [ValidateSet(
            "Overwrite", 
            "Merge", 
            "Disallow")]
        [string]$ConflictBehavior = "Overwrite",

        [Parameter(Mandatory=$true, ParameterSetName="OnPremDnsServer")]
        [switch]$OnPremDnsServer,

        [Parameter(Mandatory=$true, ParameterSetName="OnPremDnsServer")]
        [System.Collections.Generic.HashSet[string]]$AzDnsForwarderIpAddress
    )

    Assert-IsWindowsServer
    Assert-OSFeature -WindowsServerFeature "DNS", "RSAT-DNS-Server"

    $caption = "Configure DNS server"
    $verboseConfirmMessage = "This action will implement the DNS forwarding scheme as defined in the DnsForwardingRuleSet. Depending on the specified ConflictBehavior parameter, this may be a destructive operation."

    if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
        if ($OnPremDnsServer) {
            $rules = $DnsForwardingRuleSet | `
                Select-Object -ExpandProperty DnsForwardingRules | `
                Where-Object { $_.AzureResource }
        } else {
            $rules = $DnsForwardingRuleSet | `
                Select-Object -ExpandProperty DnsForwardingRules
        }

        foreach($rule in $rules) {
            $zone = Get-DnsServerZone | `
                Where-Object { $_.ZoneName -eq $rule.DomainName }

            if ($OnPremDnsServer) {
                $masterServers = $AzDnsForwarderIpAddress
            } else {
                $masterServers = $rule.MasterServers
            }

            if ($null -ne $zone) {
                switch($ConflictBehavior) {
                    "Overwrite" {
                        $zone | Remove-DnsServerZone `
                                -Confirm:$false `
                                -Force
                    }

                    "Merge" {
                        $existingMasterServers = $zone | `
                            Select-Object -ExpandProperty MasterServers | `
                            Select-Object -ExpandProperty IPAddressToString
                        
                        if ($OnPremDnsServer) {
                            $masterServers = [System.Collections.Generic.HashSet[string]]::new(
                                $AzDnsForwarderIpAddress)
                        } else {
                            $masterServers = [System.Collections.Generic.HashSet[string]]::new(
                                $masterServers)
                        }               

                        foreach($existingServer in $existingMasterServers) {
                            $masterServers.Add($existingServer) | Out-Null
                        }
                        
                        $zone | Remove-DnsServerZone `
                                -Confirm:$false `
                                -Force
                    }

                    "Disallow" {
                        throw [System.ArgumentException]::new(
                            "The DNS forwarding zone already exists", "DnsForwardingRuleSet")
                    }

                    default {
                        throw [System.ArgumentException]::new(
                            "Unexpected conflict behavior $ConflictBehavior", "ConflictBehavior")
                    }
                }
            }
            
            Add-DnsServerConditionalForwarderZone `
                    -Name $rule.DomainName `
                    -MasterServers $masterServers
            
            Clear-DnsClientCache
            Clear-DnsServerCache `
                    -Confirm:$false `
                    -Force
        }
    }
}

function Confirm-AzDnsForwarderPreReqs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [string]$VirtualNetworkResourceGroupName,

        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [string]$VirtualNetworkName,

        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [Parameter(Mandatory=$true, ParameterSetName="VNetObjectParameterSet")]
        [string]$VirtualNetworkSubnetName,

        [Parameter(Mandatory=$true, ParameterSetName="VNetObjectParameterSet")]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,

        [Parameter(Mandatory=$true, ParameterSetName="SubnetObjectParameterSet")]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]$VirtualNetworkSubnet,
        
        [Parameter(Mandatory=$false)]
        [string]$DomainToJoin,

        [Parameter(Mandatory=$false)]
        [string]$DnsForwarderRootName = "DnsFwder",

        [Parameter(Mandatory=$false)]
        [int]$DnsForwarderRedundancyCount = 2
    )

    Assert-IsDomainJoined
    Request-ADFeature
    Assert-DnsForwarderArmTemplateVersion

    # Check networking parameters: VirtualNetwork and VirtualNetworkSubnet
    switch($PSCmdlet.ParameterSetName) {
        "NameParameterSet" {
            # Get/verify virtual network is there.
            $VirtualNetwork = Get-AzVirtualNetwork `
                -ResourceGroupName $VirtualNetworkResourceGroupName `
                -Name $VirtualNetworkName `
                -ErrorAction SilentlyContinue
            
            if ($null -eq $VirtualNetwork) {
                Write-Error `
                        -Message "Virtual network $virtualNetworkName does not exist in resource group $virtualNetworkResourceGroupName." `
                        -ErrorAction Stop
            }

            # Verify subnet
            $VirtualNetworkSubnet = $VirtualNetwork | `
                Select-Object -ExpandProperty Subnets | `
                Where-Object { $_.Name -eq $VirtualNetworkSubnetName } 

            if ($null -eq $virtualNetworkSubnet) {
                Write-Error `
                        -Message "Subnet $virtualNetworkSubnetName does not exist in virtual network $($VirtualNetwork.Name)." `
                        -ErrorAction Stop
            }
        }

        "VNetObjectParameterSet" {
            # Capture information from the object
            $VirtualNetworkName = $VirtualNetwork.Name
            $VirtualNetworkResourceGroupName = $VirtualNetwork.ResourceGroupName

            # Verify/update virtual network object
            $VirtualNetwork = $VirtualNetwork | `
                Get-AzVirtualNetwork -ErrorAction SilentlyContinue
            
            if ($null -eq $VirtualNetwork) {
                Write-Error `
                    -Message "Virtual network $virtualNetworkName does not exist in resource group $virtualNetworkResourceGroupName." `
                    -ErrorAction Stop
            } 

            # Verify subnet
            $VirtualNetworkSubnet = $VirtualNetwork | `
                Select-Object -ExpandProperty Subnets | `
                Where-Object { $_.Name -eq $VirtualNetworkSubnetName } 

            if ($null -eq $VirtualNetworkSubnet) {
                Write-Error `
                        -Message "Subnet $virtualNetworkSubnetName does not exist in virtual network $($VirtualNetwork.Name)." `
                        -ErrorAction Stop
            }
        }

        "SubnetObjectParameterSet" {
            # Get resource names from the ID
            $virtualNetworkSubnetId = $VirtualNetworkSubnet.Id | Expand-AzResourceId
            $VirtualNetworkName = $virtualNetworkSubnetId["virtualNetworks"]
            $VirtualNetworkResourceGroupName = $virtualNetworkSubnetId["resourceGroups"]
            $VirtualNetworkSubnetName = $virtualNetworkSubnetId["subnets"]

            # Get/verify virtual network object
            $VirtualNetwork = Get-AzVirtualNetwork `
                -ResourceGroupName $VirtualNetworkResourceGroupName `
                -Name $VirtualNetworkName `
                -ErrorAction SilentlyContinue
            
            if ($null -eq $VirtualNetwork) {
                Write-Error `
                        -Message "Virtual network $virtualNetworkName does not exist in resource group $virtualNetworkResourceGroupName." `
                        -ErrorAction Stop
            }
            
            # Verify subnet object
            $VirtualNetworkSubnet = $VirtualNetwork | `
                Select-Object -ExpandProperty Subnets | `
                Where-Object { $_.Id -eq $VirtualNetworkSubnet.Id }
            
            if ($null -eq $VirtualNetworkSubnet) {
                Write-Error `
                        -Message "Subnet $VirtualNetworkSubnetName could not be found." `
                        -ErrorAction Stop
            }
        }

        default {
            throw [ArgumentException]::new("Unhandled parameter set $_.")
        }
    }

    # Check domain
    if ([string]::IsNullOrEmpty($DomainToJoin)) {
        $DomainToJoin = (Get-ADDomainInternal).DNSRoot
    } else {
        try {
            $DomainToJoin = (Get-ADDomainInternal -Identity $DomainToJoin).DNSRoot
        } catch {
            throw [System.ArgumentException]::new(
                "Could not find the domain $DomainToJoin", "DomainToJoin")
        }
    }

    # Get incrementor 
    $intCaster = {
        param($name, $rootName, $domainName)

        $str = $name.
            Replace(".$domainName", "").
            ToLowerInvariant().
            Replace("$($rootName.ToLowerInvariant())-", "")
        
        $i = -1
        if ([int]::TryParse($str, [ref]$i)) {
            return $i
        } else {
            return -1
        }
    }

    # Check computer names
    # not sure that the actual boundary conditions (greater than 999) being tested.
    $filterCriteria = ($DnsForwarderRootName + "-*")
    $incrementorSeed = Get-ADComputerInternal -Filter "Name -like '$filterCriteria'" | 
        Select-Object Name, 
            @{ 
                Name = "Incrementor"; 
                Expression = { $intCaster.Invoke($_.DNSHostName, $DnsForwarderRootName, $DomainToJoin) } 
            } | `
        Select-Object -ExpandProperty Incrementor | `
        Measure-Object -Maximum | `
        Select-Object -ExpandProperty Maximum
    
    if ($null -eq $incrementorSeed) {
        $incrementorSeed = -1
    }

    if ($incrementorSeed -lt 1000) {
        $incrementorSeed++
    } else {
        Write-Error `
                -Message "There are more than 1000 DNS forwarders domain joined to this domain. Chose another DnsForwarderRootName." `
                -ErrorAction Stop
    }

    $dnsForwarderNames = $incrementorSeed..($incrementorSeed+$DnsForwarderRedundancyCount-1) | `
        ForEach-Object { $DnsForwarderRootName + "-" + $_.ToString() }

    return @{
        "VirtualNetwork" = $VirtualNetwork;
        "VirtualNetworkSubnet" = $VirtualNetworkSubnet;
        "DomainToJoin" = $DomainToJoin;
        "DnsForwarderResourceIterator" = $incrementorSeed;
        "DnsForwarderNames" = $dnsForwarderNames
    }
}

function Join-AzDnsForwarder {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$DomainToJoin,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]$DnsForwarderNames
    )

    process {
        $caption = "Domain join DNS forwarders"
        $verboseConfirmMessage = "This action will domain join your DNS forwarders to your domain."
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            $odjBlobs = $DnsForwarderNames | `
                Register-OfflineMachine `
                    -Domain $DomainToJoin `
                    -ErrorAction Stop
        
            return @{ 
                "Domain" = $DomainToJoin; 
                "DomainJoinBlobs" = $odjBlobs 
            }
        }
        
    }
}

function Get-ArmTemplateObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ArmTemplateUri
    )

    process {
        $request = Invoke-WebRequest `
                -Uri $ArmTemplateUri `
                -UseBasicParsing 

        if ($request.StatusCode -ne 200) {
            Write-Error `
                    -Message "Unexpected status code when retrieving ARM template: $($request.StatusCode)" `
                    -ErrorAction Stop
        }

        return ($request.Content | ConvertFrom-Json -Depth 100)
    }
}

function Get-ArmTemplateVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSCustomObject]$ArmTemplateObject
    )

    process {
        if ($ArmTemplateObject.'$schema' -ne "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#") {
            throw [ArgumentException]::new(
                "Provided ARM template is missing `$schema property and is therefore likely malformed or not an ARM template", 
                "ArmTemplateObject")
        }

        if ($null -eq $ArmTemplateObject.contentVersion) {
            Write-Error -Message "The provided ARM template is missing a content version." -ErrorAction Stop
        }

        $templateVersion = [Version]$null
        if (![Version]::TryParse($ArmTemplateObject.contentVersion, [ref]$templateVersion)) {
            Write-Error -Message "The ARM template content version is malformed." -ErrorAction Stop
        }

        return $templateVersion
    }
}

function Assert-DnsForwarderArmTemplateVersion {
    [CmdletBinding()]
    param()

    # Check ARM template version
    $templateVersion = Get-ArmTemplateObject -ArmTemplateUri $DnsForwarderTemplate | `
        Get-ArmTemplateVersion

    if (
        $templateVersion.Major -lt $DnsForwarderTemplateVersion.Major -or 
        $templateVersion.Minor -lt $DnsForwarderTemplateVersion.Minor
    ) {
        Write-Error `
                -Message "The template for deploying DNS forwarders in the Azure repository is an older version than the AzureFilesHybrid module expects. This likely indicates that you are using a development version of the AzureFilesHybrid module and should override the DnsForwarderTemplate config parameter on module load (or in AzureFilesHybrid.psd1) to match the correct development version." `
                -ErrorAction Stop
    } elseif (
        $templateVersion.Major -gt $DnsForwarderTemplateVersion.Major -or 
        $templateVersion.Minor -gt $DnsForwarderTemplateVersion.Minor
    ) {
        Write-Error -Message "The template for deploying DNS forwarders in the Azure repository is a newer version than the AzureFilesHybrid module expects. This likely indicates that you are using an older version of the AzureFilesHybrid module and should upgrade. This can be done by getting the newest version of the module from https://github.com/Azure-Samples/azure-files-samples/releases." -ErrorAction Stop
    } else {
        Write-Verbose -Message "DNS forwarder ARM template version is $($templateVersion.ToString())."
        Write-Verbose -Message "Expected DnsForwarderTemplateVersion version is $($DnsForwarderTemplateVersion.ToString())."
    }
}

function Invoke-AzDnsForwarderDeployment {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true)]
        [string]$DnsServerResourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]$VirtualNetworkSubnet,

        [Parameter(Mandatory=$true)]
        [hashtable]$DomainJoinParameters,

        [Parameter(Mandatory=$true)]
        [string]$DnsForwarderRootName,

        [Parameter(Mandatory=$true)]
        [int]$DnsForwarderResourceIterator,

        [Parameter(Mandatory=$true)]
        [int]$DnsForwarderRedundancyCount,

        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$VmTemporaryPassword
    )

    Assert-DnsForwarderArmTemplateVersion

    # Encode ruleset
    $encodedDnsForwardingRuleSet = $DnsForwardingRuleSet | ConvertTo-EncodedJson -Depth 3

    $caption = "Deploy DNS forwarders in Azure"
    $verboseConfirmMessage = "This action will deploy the DNS forwarders in Azure."

    if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
        try {
            $templateResult = New-AzResourceGroupDeployment `
                -ResourceGroupName $DnsServerResourceGroupName `
                -TemplateUri $DnsForwarderTemplate `
                -location $VirtualNetwork.Location `
                -virtualNetworkResourceGroupName $VirtualNetwork.ResourceGroupName `
                -virtualNetworkName $VirtualNetwork.Name `
                -virtualNetworkSubnetName $VirtualNetworkSubnet.Name `
                -dnsForwarderRootName $DnsForwarderRootName `
                -vmResourceIterator $DnsForwarderResourceIterator `
                -vmResourceCount $DnsForwarderRedundancyCount `
                -dnsForwarderTempPassword $VmTemporaryPassword `
                -odjBlobs $DomainJoinParameters `
                -encodedForwardingRules $encodedDnsForwardingRuleSet `
                -ErrorAction Stop
        } catch {
            Write-Error -Message "This error message will eventually be replaced by a rollback functionality." -ErrorAction Stop
        }
    }
}

function Get-AzDnsForwarderIpAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DnsServerResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string[]]$DnsForwarderName
    )

    $nicNames = $DnsForwarderNames | `
        Select-Object @{ Name = "NIC"; Expression = { ($_ + "-NIC") } } | `
        Select-Object -ExpandProperty NIC

    $ipAddresses = Get-AzNetworkInterface -ResourceGroupName $DnsServerResourceGroupName | `
        Where-Object { $_.Name -in $nicNames } | `
        Select-Object -ExpandProperty IpConfigurations | `
        Select-Object -ExpandProperty PrivateIpAddress
    
    return $ipAddresses
}

function Update-AzVirtualNetworkDnsServers {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,

        [Parameter(Mandatory=$true)]
        [string[]]$DnsForwarderIpAddress
    )

    $caption = "Update your virtual network's DNS servers"
    $verboseConfirmMessage = "This action will update your virtual network's DNS settings."

    if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
        if ($null -eq $VirtualNetwork.DhcpOptions.DnsServers) {
            $VirtualNetwork.DhcpOptions.DnsServers = 
                [System.Collections.Generic.List[string]]::new()
        }

        foreach($ipAddress in $DnsForwarderIpAddress) {
            $VirtualNetwork.DhcpOptions.DnsServers.Add($ipAddress)
        }
        
        $VirtualNetwork | Set-AzVirtualNetwork -ErrorAction Stop | Out-Null
    }
}

function New-AzDnsForwarder {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param(
        [Parameter(Mandatory=$true)]
        [DnsForwardingRuleSet]$DnsForwardingRuleSet,

        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [string]$VirtualNetworkResourceGroupName,

        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [string]$VirtualNetworkName,

        [Parameter(Mandatory=$true, ParameterSetName="NameParameterSet")]
        [Parameter(Mandatory=$true, ParameterSetName="VNetObjectParameter")]
        [string]$VirtualNetworkSubnetName,

        [Parameter(Mandatory=$true, ParameterSetName="VNetObjectParameter")]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VirtualNetwork,

        [Parameter(Mandatory=$true, ParameterSetName="SubnetObjectParameter")]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]$VirtualNetworkSubnet,

        [Parameter(Mandatory=$false)]
        [string]$DnsServerResourceGroupName,
        
        [Parameter(Mandatory=$false)]
        [string]$DnsForwarderRootName = "DnsFwder",

        [Parameter(Mandatory=$false)]
        [System.Security.SecureString]$VmTemporaryPassword,

        [Parameter(Mandatory=$false)]
        [string]$DomainToJoin,

        [Parameter(Mandatory=$false)]
        [int]$DnsForwarderRedundancyCount = 2,

        [Parameter(Mandatory=$false)]
        [System.Collections.Generic.HashSet[string]]$OnPremDnsHostNames,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$SkipParentDomain
    )

    $caption = "Create Azure DNS forwarders"
    $verboseConfirmMessage = "This action will fully configure DNS forwarding end-to-end, including deploying DNS forwarders in Azure VMs and configuring on-premises DNS to forward the appropriate zones to Azure."

    if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
        $confirmParameters = @{}

        switch($PSCmdlet.ParameterSetName) {
            "NameParameterSet" {
                $confirmParameters += @{ 
                    "VirtualNetworkResourceGroupName" = $VirtualNetworkResourceGroupName;
                    "VirtualNetworkName" = $VirtualNetworkName;
                    "VirtualNetworkSubnetName" = $VirtualNetworkSubnetName;
                }
            }

            "VNetObjectParameter" {
                $confirmParameters += @{
                    "VirtualNetwork" = $VirtualNetwork;
                    "VirtualNetworkSubnetName" = $VirtualNetworkSubnetName
                }
            }

            "SubnetObjectParameter" {
                $confirmParameters += @{
                    "VirtualNetworkSubnet" = $VirtualNetworkSubnet
                }
            }

            default {
                throw [ArgumentException]::new("Unhandled parameter set")
            }
        }

        if ($PSBoundParameters.ContainsKey("DomainToJoin")) {
            $confirmParameters += @{
                "DomainToJoin" = $DomainToJoin
            }
        }

        if ($PSBoundParameters.ContainsKey("DnsForwarderRootName")) {
            $confirmParameters += @{
                "DnsForwarderRootName" = $DnsForwarderRootName
            }
        }

        if ($PSBoundParameters.ContainsKey("DnsForwarderRedundancyCount")) {
            $confirmParameters += @{ 
                "DnsForwarderRedundancyCount" = $DnsForwarderRedundancyCount
            }
        }

        $verifiedObjs = Confirm-AzDnsForwarderPreReqs @confirmParameters -ErrorAction Stop
        $VirtualNetwork = $verifiedObjs.VirtualNetwork
        $VirtualNetworkSubnet = $verifiedObjs.VirtualNetworkSubnet
        $DomainToJoin = $verifiedObjs.DomainToJoin
        $DnsForwarderResourceIterator = $verifiedObjs.DnsForwarderResourceIterator
        $DnsForwarderNames = $verifiedObjs.DnsForwarderNames

        # Create resource group for the DNS forwarders, if it hasn't already
        # been created. The resource group will have the same location as the vnet.
        if ($PSBoundParameters.ContainsKey("DnsServerResourceGroupName")) {
            $dnsServerResourceGroup = Get-AzResourceGroup | `
                Where-Object { $_.ResourceGroupName -eq $DnsServerResourceGroupName }

            if ($null -eq $dnsServerResourceGroup) { 
                $dnsServerResourceGroup = New-AzResourceGroup `
                        -Name $DnsServerResourceGroupName `
                        -Location $VirtualNetwork.Location
            }
        } else {
            $DnsServerResourceGroupName = $VirtualNetwork.ResourceGroupName
        }       

        # Get names of on-premises host names
        if ($null -eq $OnPremDnsHostNames) {
            $onPremDnsServers = $DnsForwardingRuleSet.DnsForwardingRules | `
                Where-Object { $_.AzureResource -eq $false } | `
                Select-Object -ExpandProperty MasterServers
            
            $OnPremDnsHostNames = $onPremDnsServers | `
                ForEach-Object { [System.Net.Dns]::GetHostEntry($_) } | `
                Select-Object -ExpandProperty HostName
        }

        $domainJoinParameters = Join-AzDnsForwarder `
                -DomainToJoin $DomainToJoin `
                -DnsForwarderNames $DnsForwarderNames `
                -Confirm:$false

        if (!$PSBoundParameters.ContainsKey("VmTemporaryPassword")) {
            $VmTemporaryPassword = Get-RandomString `
                    -StringLength 15 `
                    -CaseSensitive `
                    -AsSecureString
        }
        
        Invoke-AzDnsForwarderDeployment `
                -DnsForwardingRuleSet $DnsForwardingRuleSet `
                -DnsServerResourceGroupName $DnsServerResourceGroupName `
                -VirtualNetwork $VirtualNetwork `
                -VirtualNetworkSubnet $VirtualNetworkSubnet `
                -DomainJoinParameters $domainJoinParameters `
                -DnsForwarderRootName $DnsForwarderRootName `
                -DnsForwarderResourceIterator $DnsForwarderResourceIterator `
                -DnsForwarderRedundancyCount $DnsForwarderRedundancyCount `
                -VmTemporaryPassword $VmTemporaryPassword `
                -ErrorAction Stop `
                -Confirm:$false

        $ipAddresses = Get-AzDnsForwarderIpAddress `
                -DnsServerResourceGroupName $DnsServerResourceGroupName `
                -DnsForwarderName $DnsForwarderNames

        Update-AzVirtualNetworkDnsServers `
                -VirtualNetwork $VirtualNetwork `
                -DnsForwarderIpAddress $ipAddresses `
                -Confirm:$false

        foreach($dnsForwarder in $dnsForwarderNames) {
            Restart-AzVM `
                    -ResourceGroupName $DnsServerResourceGroupName `
                    -Name $dnsForwarder | `
                Out-Null
        }

        foreach($server in $OnPremDnsHostNames) {
            if ($PSBoundParameters.ContainsKey("Credential")) {
                $session = Initialize-RemoteSession `
                        -ComputerName $server `
                        -Credential $Credential `
                        -InstallViaCopy `
                        -OverrideModuleConfig @{ 
                            SkipPowerShellGetCheck = $true;
                            SkipAzPowerShellCheck = $true;
                            SkipDotNetFrameworkCheck = $true
                        }
            } else {
                $session = Initialize-RemoteSession `
                        -ComputerName $server `
                        -InstallViaCopy `
                        -OverrideModuleConfig @{ 
                            SkipPowerShellGetCheck = $true;
                            SkipAzPowerShellCheck = $true;
                            SkipDotNetFrameworkCheck = $true
                        }
            }            
            
            $serializedRuleSet = $DnsForwardingRuleSet | ConvertTo-Json -Compress -Depth 3
            Invoke-Command `
                    -Session $session `
                    -ArgumentList $serializedRuleSet, ([string[]]$ipAddresses) `
                    -ScriptBlock {
                        $DnsForwardingRuleSet = [DnsForwardingRuleSet]::new(($args[0] | ConvertFrom-Json))
                        $dnsForwarderIPs = ([string[]]$args[1])

                        Push-DnsServerConfiguration `
                                -DnsForwardingRuleSet $DnsForwardingRuleSet `
                                -OnPremDnsServer `
                                -AzDnsForwarderIpAddress $dnsForwarderIPs `
                                -Confirm:$false
                    }
        }    
        
        Clear-DnsClientCacheInternal
    }
}
#endregion

#region DFS-N cmdlets
#endregion

#region Share level permissions migration cmdlets
function Move-OnPremSharePermissionsToAzureFileShare
{
    <#
    .SYNOPSIS
    Maps local share permissions to Azure RBAC's built-in roles for files. Applies corresponding built-in roles to domain user's identity in Azure AD.
    .DESCRIPTION
    On-prem share permissions applied on domain users will be mapped to Azure RBAC's built-in roles. And these built-in roles will be assigned to domain user's identity in Azure AD.
    .OUTPUTS
    Boolean, If $CommitChanges is False, this functions checks if share permissions can be migrated to cloud without any failures. Returns True if migration is possible without errors.
    If $CommitChanges is True, this function migrates on-prem share permissions to azure file share RBAC permissions. If there any errors are encountered particualr share permission migration is skipped and next permission in the list in processed.
    .EXAMPLE
    PS C:\> Move-OnPremSharePermissionsToAzureFileShare -LocalSharename "<localsharename>" -Destinationshare "<destinationshharename>" -ResourceGroupName "<resourceGroupName>" -StorageAccountName "<storageAccountName>" -CommitChanges $False -StopOnAADUserLookupFailure $True -AutoFitSharePermissionsOnAAD $True
    #>

    Param(
         [Parameter(Mandatory=$true, Position=0, HelpMessage="Name of the share present on-prem.")]
         [string]$LocalShareName,

         [Parameter(Mandatory=$true, Position=1, HelpMessage="Name of the share on Azure storage account.")]
         [string]$DestinationShareName,

         [Parameter(Mandatory=$true, Position=2, HelpMessage="Resource group name of storage account.")]
         [string]$ResourceGroupName,

         [Parameter(Mandatory=$true, Position=3, HelpMessage="Storage account name on Azure.")]
         [string]$StorageAccountName,

         [Parameter(Mandatory=$true, Position=4, HelpMessage="If false, the tool just checks for possible errors and reports back without making any changes on the cloud.")]
         [bool]$CommitChanges,

         [Parameter(Mandatory=$false, Position=5, HelpMessage="If true, ACL migration will be stopped upon failure to lookup local user on Azure AD.")]
         [bool]$StopOnAADUserLookupFailure = $true,

         [Parameter(Mandatory=$false, Position=6, HelpMessage="If true, permissions will be mapped to closest available on built-in roles in Azure RBAC.")]
         [bool]$AutoFitSharePermissionsOnAAD = $true
        )

    # Certain accounts in a domain server will not be represented in Azure AD.
    [String[]]$wellKnowAccountName = 'Everyone', 'BUILTIN\Administrators', 'Domain', 'Authenticated Users', 'Users', 'SYSTEM', 'Domain Admins', 'Domain Users'
    $wellKnownAccountNamesSet = [System.Collections.Generic.HashSet[String]]::new([System.Collections.Generic.IEnumerable[String]]$wellKnowAccountName)

    $roleAssignmentsDoneList = New-Object System.Collections.Generic.List[Microsoft.Azure.Commands.Resources.Models.Authorization.PSRoleAssignment]
    $roleAssignmentsSkippedAccountsForMissingRoles = New-Object System.Collections.Generic.List[CimInstance]
    $roleAssignmentsSkippedAccountsForMissingIdentity = New-Object System.Collections.Generic.List[CimInstance]
    $roleAssignmentsSkippedAccountsForHavingRoleAlready = New-Object System.Collections.Generic.List[CimInstance]
    $roleAssignmentsDoneAccounts = New-Object System.Collections.Generic.List[CimInstance]
    $roleAssignmentsPossibleWithoutAnySkips = $True

    # Verify the Storage account and file share exist on the cloud.
    try
    {
        $StorageAccountObj = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
    }
    catch
    {
        Write-Error -Message "Caught exception: $_" -ErrorAction Stop
    }

    if($StorageAccountObj -eq $null)
    {
        throw "The Storage Account doesn't exist. To create the Storage account and connect it to an active directory, 
                                    please follow the link https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable"
    }

    if($StorageAccountObj.AzureFilesIdentityBasedAuth.DirectoryServiceOptions -ne 'AD')
    {
        throw "To Proceed, you need to have Storage Account connected to an Active Directory.
                                        Refer the link for details - https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable"
    }

    try
    {
        $accountKey = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | Where-Object {$_.KeyName -like "key1"}
        $storageAccountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $accountKey.Value
    }
    catch
    {
        Write-Error "Caught exception: $_" -ErrorAction Stop
    }

    Write-Verbose -Message "Checking if the destination share exists"

    $cloudShare = Get-AzStorageShare -Context $storageAccountContext -Name $DestinationShareName -Erroraction 'silentlycontinue'

    # If the destination share does not exist, the following will create a new share.
    if($cloudShare -eq $null)
    {
        Write-Verbose -Message  "The Destination Share doesn't exist. Creating a new share with the name provided"
        try
        {
            $cloudShare = New-AzStorageShare -Name $DestinationShareName -Context $storageAccountContext
        }
        catch
        {
            Write-Error "Caught exception: $_" -ErrorAction Stop
        }
    }

    Write-Verbose -Message "Getting the local SMB share access details"
    $localSmbShareAccess = Get-SmbShareAccess -Name $LocalShareName

    if ($localSmbShareAccess -eq $null)
    {
        throw "Could not find share with name $LocalShareName."
    }

    Write-Host "Local SMB share access details"

    $localSmbShareAccess | Format-Table | Out-String|% {Write-Host $_}

    # Run through ACL of the local share.
    foreach($smbShareAccessControl in $localSmbShareAccess)
    {
        $account=$smbShareAccessControl.AccountName
        $strAccessRight =[string] $smbShareAccessControl.AccessRight
        $strAccessControlType = [string] $smbShareAccessControl.AccessControlType
        
        if($wellKnownAccountNamesSet.Contains($account))
        {
            $roleAssignmentsSkippedAccountsForMissingIdentity.Add($smbShareAccessControl)
            continue
        }

        $objUser = New-Object System.Security.Principal.NTAccount($account)
        $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])

        Write-Verbose -Message "Mapping domain user/group - $account to its corresponding identity on Azure AAD"

        #Geting the OID of domain user/group using its SID
        try
        {
            $aadUser = Get-AzureADUser -Filter "OnPremisesSecurityIdentifier eq '$strSID'"
        }
        catch
        {
            Write-Error "Caught exception: $_" -ErrorAction Stop
        }

        if ($aadUser -ne $null)
        {
            Write-Verbose -Message "Domain user/group's identity retreived from AAD - $($aadUser.UserPrincipalName)"

            #Assign Rbac for OID extracted from above.
            $roleDefinition = $null

            If($strAccessControlType.Contains("Allow"))
            {
                if($strAccessRight.Contains("Read"))
                {
                    # Storage File Data SMB Share Reader - Built in role definition has below Id.
                    $roleDefinition = Get-AzRoleDefinition -Id aba4ae5f-2193-4029-9191-0cb91df5e314
                }
                elseif($strAccessRight.Contains("Change"))
                {
                    # Storage File Data SMB Share Elevated Contributor - Built in role has below Id.
                    $roleDefinition = Get-AzRoleDefinition -Id a7264617-510b-434b-a828-9731dc254ea7
                }
                elseif($strAccessRight.Contains("Full") -And $AutoFitSharePermissionsOnAAD -eq $true)
                {
                    # Storage File Data SMB Share Elevated Contributor - Built in role has below Id.
                    $roleDefinition = Get-AzRoleDefinition -Id a7264617-510b-434b-a828-9731dc254ea7
                }
            }
            else
            {
                # On deny, User should create custom role definitions.
                $roleAssignmentsSkippedAccountsForMissingRoles.Add($smbShareAccessControl)
            }

            if ($roleDefinition -ne $null -And $CommitChanges -eq $true)
            {
                Write-Verbose -Message "Assigning corresponding RBAC role to the user/group with scope set to the destination share."

                #Constrain the scope to the target file share
                $storageAccountPath = $StorageAccountObj.Id
                $scope = "$storageAccountPath/fileServices/default/fileshares/$DestinationShareName"

                $roleAssignments = Get-AzRoleAssignment -Scope $scope -ObjectId $aadUser.ObjectId

                #Check to see if the role is already assigned to the user/group.
                $isRoleAssignedAlready = $False;

                if($roleAssignments -ne $null )
                {
                    foreach($roleAssignment in $roleAssignments)
                    {
                        if($roleAssignment.RoleDefinitionName -eq $roleDefinition.Name)
                        {
                            Write-Verbose -Message "Role assignment present already, skipping"
                            $isRoleAssignedAlready = $True
                            $roleAssignmentsSkippedAccountsForHavingRoleAlready.Add($smbShareAccessControl)
                            break;
                        }
                    }
                }

                if ($isRoleAssignedAlready -eq $False)
                {
                    Write-Verbose -Message "Assigning RBAC role to the user/group : $account  with the role : $($roleDefinition.Name)"
                    #Assign the custom role to the target identity with the specified scope.
                    $newRoleAssignment = New-AzRoleAssignment -ObjectId $aadUser.ObjectId -RoleDefinitionId $roleDefinition.Id -Scope $scope

                    $roleAssignmentsDoneAccounts.Add($smbShareAccessControl)
                    $roleAssignmentsDoneList.Add($newRoleAssignment)
                }
            }
        }
        else
        {
            $roleAssignmentsSkippedAccountsForMissingIdentity.Add($smbShareAccessControl)
            If ($CommitChanges -eq $true)
            {
                If ($StopOnAADUserLookupFailure)
                {
                    Write-Error -Message "Could not find an identity on AAD for domain user - '$account'. Please confirm AD connect is complete." -ErrorAction stop
                }
                else
                {
                    Write-Error -Message "Could not find an identity on AAD for domain user - '$account', Continuing" -ErrorAction Continue
                }
            }
        }
    }

    If ($CommitChanges -eq $false)
    {
        If ($roleAssignmentsSkippedAccountsForMissingIdentity.Count -ne 0)
        {
            Write-Host "Following Accounts do not have corresponding identities in Azure AD. If you continue, these account's access control will be skipped"

            $roleAssignmentsPossibleWithoutAnySkips = $False
            $roleAssignmentsSkippedAccountsForMissingIdentity | Format-Table | Out-String|% {Write-Host $_}
        }

        If ($roleAssignmentsSkippedAccountsForMissingRoles.Count -ne 0)
        {
            Write-Host "Following Accounts do not have corresponding access right/control in Azure AD. If you continue, these account's access control will be skipped"

            $roleAssignmentsPossibleWithoutAnySkips = $False
            $roleAssignmentsSkippedAccountsForMissingRoles | Format-Table | Out-String|% {Write-Host $_}
        }
    }
    else
    {
        If ($roleAssignmentsSkippedAccountsForMissingIdentity.Count -ne 0)
        {
            Write-Host "Following Accounts do not have corresponding identities in Azure AD. Skipped ACL migration."

            $roleAssignmentsSkippedAccountsForMissingIdentity | Format-Table | Out-String|% {Write-Host $_}
        }

        If ($roleAssignmentsSkippedAccountsForMissingRoles.Count -ne 0)
        {
            Write-Host "Following Accounts do not have corresponding access right/control in Azure AD. Skipped ACL migration."

            $roleAssignmentsSkippedAccountsForMissingRoles | Format-Table | Out-String|% {Write-Host $_}
        }

        If ($roleAssignmentsSkippedAccountsForHavingRoleAlready.Count -ne 0)
        {
            Write-Host "Following Accounts already have access to the share at share scope or higher. Skipped ACL migration."

            $roleAssignmentsSkippedAccountsForHavingRoleAlready | Format-Table | Out-String|% {Write-Host $_}
        }

        If ($roleAssignmentsDoneAccounts.Count -ne 0)
        {
            Write-Host "Below accounts were mapped to Azure AD roles"

            $roleAssignmentsDoneAccounts | Format-Table | Out-String|% {Write-Host $_}
        }

        If ($roleAssignmentsDoneList.Count -ne 0)
        {
            Write-Host "`nSuccessful role assignments:"

            foreach($roleAssignment in $roleAssignmentsDoneList)
            {
                $roleAssignment
            }
        }
    }
    return $roleAssignmentsPossibleWithoutAnySkips
}
#endregion

#region Actions to run on module load
$AzurePrivateDnsIp = [string]$null
$DnsForwarderTemplateVersion = [Version]$null
$DnsForwarderTemplate = [string]$null
$SkipPowerShellGetCheck = $false
$SkipAzPowerShellCheck = $false
$SkipDotNetFrameworkCheck = $false

function Invoke-ModuleConfigPopulate {
    <#
    .SYNOPSIS
    Populate module configuration parameters.

    .DESCRIPTION
    This cmdlet wraps the PrivateData object as defined in AzureFilesHybrid.psd1, as well as module parameter OverrideModuleConfig. If an override is specified, that value will be used, otherwise, the value from the PrivateData object will be used.

    .PARAMETER OverrideModuleConfig
    The OverrideModuleConfig specified in the parameters of the module, at the beginning of the module.

    .EXAMPLE
    Invoke-ModuleConfigPopulate -OverrideModuleConfig @{}
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [hashtable]$OverrideModuleConfig
    )

    $DefaultModuleConfig = $MyInvocation.MyCommand.Module.PrivateData["Config"]

    if ($OverrideModuleConfig.ContainsKey("AzurePrivateDnsIp")) {
        $script:AzurePrivateDnsIp = $OverrideModuleConfig["AzurePrivateDnsIp"]
    } else {
        $script:AzurePrivateDnsIp = $DefaultModuleConfig["AzurePrivateDnsIp"]
    }

    if ($OverrideModuleConfig.ContainsKey("DnsForwarderTemplateVersion")) {
        $script:DnsForwarderTemplateVersion = [Version]$null
        $v = [Version]$null
        if (![Version]::TryParse($OverrideModuleConfig["DnsForwarderTemplateVersion"], [ref]$v)) {
            Write-Error `
                    -Message "Unexpected DnsForwarderTemplateVersion version value specified in overrides." `
                    -ErrorAction Stop
        }

        $script:DnsForwarderTemplateVersion = $v
    } else {
        $script:DnsForwarderTemplateVersion = [Version]$null
        $v = [Version]$null
        if (![Version]::TryParse($DefaultModuleConfig["DnsForwarderTemplateVersion"], [ref]$v)) {
            Write-Error `
                    -Message "Unexpected DnsForwarderTemplateVersion version value specified in AzFilesHybrid DefaultModuleConfig." `
                    -ErrorAction Stop
        }
        
        $script:DnsForwarderTemplateVersion = $v
    }

    if ($OverrideModuleConfig.ContainsKey("DnsForwarderTemplate")) {
        $script:DnsForwarderTemplate = $OverrideModuleConfig["DnsForwarderTemplate"]
    } else {
        $script:DnsForwarderTemplate = $DefaultModuleConfig["DnsForwarderTemplate"]
    }

    if ($OverrideModuleConfig.ContainsKey("SkipPowerShellGetCheck")) {
        $script:SkipPowerShellGetCheck = $OverrideModuleConfig["SkipPowerShellGetCheck"]
    } else {
        $script:SkipPowerShellGetCheck = $DefaultModuleConfig["SkipPowerShellGetCheck"]
    }

    if ($OverrideModuleConfig.ContainsKey("SkipAzPowerShellCheck")) {
        $script:SkipAzPowerShellCheck = $OverrideModuleConfig["SkipAzPowerShellCheck"]
    } else {
        $script:SkipAzPowerShellCheck = $DefaultModuleConfig["SkipAzPowerShellCheck"]
    }

    if ($OverrideModuleConfig.ContainsKey("SkipDotNetFrameworkCheck")) {
        $script:SkipDotNetFrameworkCheck = $OverrideModuleConfig["SkipDotNetFrameworkCheck"]
    } else {
        $script:SkipDotNetFrameworkCheck = $DefaultModuleConfig["SkipDotNetFrameworkCheck"]
    }
}

Invoke-ModuleConfigPopulate `
        -OverrideModuleConfig $OverrideModuleConfig

if ((Get-OSPlatform) -eq "Windows") {
    if ($PSVersionTable.PSEdition -eq "Desktop") {
        if (!$SkipDotNetFrameworkCheck) {
            Assert-DotNetFrameworkVersion `
                    -DotNetFrameworkVersion "Framework4.7.2"
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = ([Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls13)
}

if (!$SkipPowerShellGetCheck) {
    Request-PowerShellGetModule
}

if (!$SkipAzPowerShellCheck) {
    Request-AzPowerShellModule
}
#endregion
