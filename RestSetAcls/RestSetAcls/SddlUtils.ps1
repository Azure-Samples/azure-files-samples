enum SecurityDescriptorFormat {
    Sddl
    Binary
    Base64
}

function ConvertTo-SecurityDescriptor {
    [CmdletBinding(DefaultParameterSetName = "Sddl")]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Sddl")]
        [string]$Sddl,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Base64")]
        [string]$Base64,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Binary")]
        [string]$Binary
    )

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "Sddl" {
                # There are multiple ways to parse SDDL, but RawSecurityDescriptor is the most complete.
                # 
                # ConvertFrom-SddlString builds a SecurityDescriptorInfo, where the raw view is a CommonSecurityDescriptor (which is a subclass of RawSecurityDescriptor).
                # However, CommonSecurityDescriptor drops the inheritance and propagation flags, which are important for our use case.
                # (see https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/ConvertFrom-SddlString.cs)
                #
                # The .NET SDK has System.Security.AccessControl.DirectorySecurity and System.Security.AccessControl.FileSecurity. On both of these,
                # we can parse SDDL with the SetSecurityDescriptorSddlForm method. DirectorySecurity keeps the inheritance and propagation flags, and FileSecurity does not.
                # This seems like a good candidate but there is a bug on PowerShell 7 where this method doesn't work.
                # (see https://github.com/PowerShell/PowerShell/issues/19094)
                return [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
            }
            "Base64" {
                return [System.Security.AccessControl.RawSecurityDescriptor]::new([System.Convert]::FromBase64String($Base64), 0)
            }
            "Binary" {
                return [System.Security.AccessControl.RawSecurityDescriptor]::new($Binary, 0)
            }
        }
    }
}

function ConvertFrom-SecurityDescriptor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [SecurityDescriptorFormat]$OutputFormat = [SecurityDescriptorFormat]::Sddl
    )

    process {
        switch ($OutputFormat) {
            "Sddl" {
                return $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
            }
            "Binary" {
                $binary = New-Object byte[] $descriptor.BinaryLength
                $descriptor.GetBinaryForm($binary, 0)
                return $binary
            }
            "Base64" {
                $binary = New-Object byte[] $descriptor.BinaryLength
                $descriptor.GetBinaryForm($binary, 0)
                return [System.Convert]::ToBase64String($binary)
            }
        }
    }
}

function Get-AllAceFlagsMatch {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$EnabledFlags,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$DisabledFlags
    )

    foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
        $hasAllBitsFromEnabledFlags = ([int]$ace.AceFlags -band [int]$EnabledFlags) -eq [int]$EnabledFlags
        $hasNoBitsFromDisabledFlags = ([int]$ace.AceFlags -band [int]$DisabledFlags) -eq 0
        if (-not ($hasAllBitsFromEnabledFlags -and $hasNoBitsFromDisabledFlags)) {
            return $false
        }
    }

    return $true
}

function Set-AceFlags {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$EnableFlags,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$DisableFlags
    )

    if ([int]$EnableFlags -band [int]$DisableFlags) {
        throw "Enable and disable flags cannot overlap"
    }

    # Create new ACEs with updated flags
    $newAces = $SecurityDescriptor.DiscretionaryAcl | ForEach-Object {
        $aceFlags = ([int]$_.AceFlags -bor [int]$EnableFlags) -band (-bnot [int]$DisableFlags)

        if ($_.GetType().Name -eq "CommonAce") {
            [System.Security.AccessControl.CommonAce]::new(
                $aceFlags,
                $_.AceQualifier,
                $_.AccessMask,
                $_.SecurityIdentifier,
                $_.IsCallback,
                $_.GetOpaque())
        }
        else {
            throw "Unsupported ACE type: $($_.GetType().Name)"
        }
    }
    
    # Remove all old ACEs
    for ($i = $SecurityDescriptor.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
        $SecurityDescriptor.DiscretionaryAcl.RemoveAce($i) | Out-Null
    }
    
    # Add all new ACEs
    for ($i = 0; $i -lt $newAces.Count; $i++) {
        $SecurityDescriptor.DiscretionaryAcl.InsertAce($i, $newAces[$i]) | Out-Null
    }
}

<#
.SYNOPSIS
Object-specific rights for files and folders.
#>
enum SpecificRights {
    FILE_READ_DATA = 0x1
    FILE_LIST_DIRECTORY = 0x1
    FILE_WRITE_DATA = 0x2
    FILE_ADD_FILE = 0x2
    FILE_APPEND_DATA = 0x4
    FILE_ADD_SUBDIRECTORY = 0x4
    FILE_READ_EA = 0x8
    FILE_WRITE_EA = 0x10
    FILE_EXECUTE = 0x20
    FILE_TRAVERSE = 0x20
    FILE_DELETE_CHILD = 0x40
    FILE_READ_ATTRIBUTES = 0x80
    FILE_WRITE_ATTRIBUTES = 0x100
}

<#
.SYNOPSIS
Standard rights for any type of securable object (including files and folders).
#>
enum StandardRights {
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
}

<#
.SYNOPSIS
These are the basic permissions, as displayed by the Windows File Explorer.
We have also been calling these "composite rights".
#>
enum BasicPermissions {
    # 278 is obtained via:
    #    [SpecificRights]::FILE_WRITE_DATA -bor
    #    [SpecificRights]::FILE_APPEND_DATA -bor
    #    [SpecificRights]::FILE_WRITE_EA -bor
    #    [SpecificRights]::FILE_WRITE_ATTRIBUTES
    WRITE = 278

    # 131209 is obtained via:
    #    [SpecificRights]::FILE_READ_DATA -bor
    #    [SpecificRights]::FILE_READ_EA -bor
    #    [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #    [StandardRights]::READ_CONTROL
    READ = 131209
    
    # 131241 is obtained via:
    #   [BasicPermissions]::READ -bor [SpecificRights]::FILE_EXECUTE
    READ_AND_EXECUTE = 131241

    # 197055 is obtained via:
    #   [BasicPermissions]::READ_AND_EXECUTE -bor
    #   [BasicPermissions]::WRITE -bor
    #   [StandardRights]::DELETE
    MODIFY = 197055

    # 2032127 is obtained via:
    #   [BasicPermissions]::MODIFY -bor
    #   [SpecificRights]::FILE_DELETE_CHILD -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER -bor
    #   [StandardRights]::SYNCHRONIZE
    FULL_CONTROL = 2032127
}

class AccessMask {
    [int]$Value

    AccessMask([int]$mask) {
        $this.Value = $this.Normalize($mask)
    }

    [int]Normalize([int]$mask) {
        return $mask -band 0xFFFFFFFF
    }

    [bool]Has([int]$permission) {
        return ($this.Value -band $permission) -eq $permission
    }

    [Void]Add([int]$permission) {
        $this.Value = $this.Value -bor $permission
    }

    [Void]Remove([int]$permission) {
        $this.Value = $this.Value -band -bnot $permission
    }
}


function Write-SecurityDescriptor {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$descriptor
    )

    $controlFlagsHex = "0x{0:X}" -f [int]$descriptor.ControlFlags
    
    Write-Host "Owner: $($PSStyle.Foreground.Cyan)$($descriptor.Owner)$($PSStyle.Reset)"
    Write-Host "Group: $($PSStyle.Foreground.Cyan)$($descriptor.Group)$($PSStyle.Reset)"
    Write-Host "ControlFlags: $($PSStyle.Foreground.Cyan)$controlFlagsHex$($PSStyle.Reset) ($($descriptor.ControlFlags))"
    Write-Host "DiscretionaryAcl:"
    Write-Acl $descriptor.DiscretionaryAcl
    Write-Host "SystemAcl:"
    Write-Acl $descriptor.SystemAcl
}

function Write-Acl {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawAcl]$acl
    )

    if ($acl -eq $null) {
        Write-Host "    Not present"
        return
    }

    Write-Host "    Revision:     $($($PSStyle.Foreground.Cyan))$($acl.Revision)$($PSStyle.Reset)"
    Write-Host "    BinaryLength: $($($PSStyle.Foreground.Cyan))$($acl.BinaryLength)$($PSStyle.Reset)"
    Write-Host "    AceCount:     $($($PSStyle.Foreground.Cyan))$($acl.Count)$($PSStyle.Reset)"
    $i = 0
    foreach ($ace in $acl) {
        $aceTypeHex = "0x{0:X}" -f [int]$ace.AceType
        $aceSizeHex = "0x{0:X}" -f [int]$ace.BinaryLength
        $inheritFlagsHex = "0x{0:X}" -f [int]$ace.InheritanceFlags
        $propagationFlagsHex = "0x{0:X}" -f [int]$ace.PropagationFlags
        $accessMaskHex = "0x{0:X}" -f [int]$ace.AccessMask

        Write-Host "    Ace $($PSStyle.Foreground.Green)${i}$($PSStyle.Reset):"
        Write-Host "        Ace Sid:          $($PSStyle.Foreground.Cyan)$($ace.SecurityIdentifier)$($PSStyle.Reset)"
        Write-Host "        AceType:          $($PSStyle.Foreground.Cyan)$aceTypeHex$($PSStyle.Reset) ($($ace.AceType))"
        Write-Host "        AceSize:          $($PSStyle.Foreground.Cyan)$aceSizeHex$($PSStyle.Reset) ($($ace.BinaryLength))"
        Write-Host "        InheritFlags:     $($PSStyle.Foreground.Cyan)$inheritFlagsHex$($PSStyle.Reset) ($($ace.InheritanceFlags))"
        Write-Host "        PropagationFlags: $($PSStyle.Foreground.Cyan)$propagationFlagsHex$($PSStyle.Reset) ($($ace.PropagationFlags))"
        Write-Host "        Access Mask:      $($PSStyle.Foreground.Cyan)$accessMaskHex$($PSStyle.Reset) ($($ace.AccessMask))"
        Write-AccessMask $ace.AccessMask
        $i++
    }
}

function Write-AccessMask {
    param (
        [Parameter(Mandatory = $true)]
        [int]$accessMask
    )

    $mask = [AccessMask]::new($accessMask)

    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
    
    Write-Host "            simplified list:"
    foreach ($key in [Enum]::GetValues([BasicPermissions])) {
        $value = $key.value__
        if ($mask.Has($value)) {
            Write-Host "                $($PSStyle.Foreground.Green)$checkmark$($PSStyle.Reset) $key"
        } else {
            Write-Host "                $($PSStyle.Foreground.Red)$cross$($PSStyle.Reset) $key"
        }
    }

    Write-Host "            full list:"
    foreach ($key in [Enum]::GetValues([SpecificRights]) + [Enum]::GetValues([StandardRights])) {
        $value = $key.value__
        if ($mask.Has($value)) {
            Write-Host "                $key"
            $mask.Remove($value)
        }
    }

    if ($mask.Value -ne 0) {
        $hex = "0x{0:X}" -f $mask.Value
        Write-Host "                  Others: $hex"
    }
}

