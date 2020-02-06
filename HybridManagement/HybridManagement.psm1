using namespace System
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

function Test-IsElevatedSession {
    <#
    .SYNOPSIS
    Check if the session is elevated and throw an error if it isn't.
    
    .DESCRIPTION
    This cmdlet uses the Get-IsElevatedSession to throw a nice error message to the user if the session isn't elevated.
    
    .EXAMPLE
    Test-IsElevatedSession
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
    This cmdlet is a wrapper around the System.Runtime.InteropServices.RuntimeInformation .NET standard class 
    that makes it easier to work with in PowerShell 5.1/6/7/etc. $IsWindows, etc. is defined in PS6+, however
    since it's not defined in PowerShell 5.1, it's not incredibly useful for writing PowerShell code meant to 
    be executed in either language version. As older versions of .NET Framework do not support the 
    RuntimeInformation .NET standard class, if the PSEdition is "Desktop", by default you're running on Windows,
    since only "Core" releases are cross-platform.

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

function Get-OSVersion {
    <#
    .SYNOPSIS
    Get the version number of the OS.

    .DESCRIPTION
    This cmdlet provides the OS's internal version number, for example 10.0.18363.0 for Windows 10, 
    version 1909 (the public release). This cmdlet is not yet defined on Linux/macOS
    sessions.

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
    This cmdlet provides the installation type of the Windows OS, primarily to allow for cmdlet behavior changes depending 
    on whether the cmdlet is being run on a Windows client ("Client") or a Windows Server ("Server", "ServerCore"). This cmdlet
    is (obviously) only available for Windows PowerShell sessions and will return a PlatformNotSupportedException for non-Windows
    sessions.

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

    if ((Get-OSPlatform) -ne "Windows") {
        throw [System.PlatformNotSupportedException]::new("Get-WindowsInstallationType is only supported in Windows environments.")
    }

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
    Get the list of available/installed features for your OS. Currently this cmdlet only works for Windows OSes,
    but works for both Windows client and Windows Server, which among them provide three different ways of enabling/disabling
    features (if there are more than three, this cmdlet doesn't suppor them yet).

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
                    Test-IsElevatedSession

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
    This cmdlet will use the underlying OS-specific feature installation methods to install the requested feature(s).
    This is currently Windows only.

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
                Test-IsElevatedSession
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