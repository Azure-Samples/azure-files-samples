function Get-AllAceFlagsMatch {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$EnabledFlags,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$DisabledFlags
    )

    process {
        foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
            $hasAllBitsFromEnabledFlags = ([int]$ace.AceFlags -band [int]$EnabledFlags) -eq [int]$EnabledFlags
            $hasNoBitsFromDisabledFlags = ([int]$ace.AceFlags -band [int]$DisabledFlags) -eq 0
            if (-not ($hasAllBitsFromEnabledFlags -and $hasNoBitsFromDisabledFlags)) {
                return $false
            }
        }

        return $true
    }
}

function Set-AceFlags {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification = "We are setting the AceFlags property.")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSUseShouldProcessForStateChangingFunctions",
        "",
        Justification = "No external side effects, just changes the security descriptor object in-place. So no real value to supporting -WhatIf.")]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$EnableFlags,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AceFlags]$DisableFlags
    )

    begin {
        if ([int]$EnableFlags -band [int]$DisableFlags) {
            throw "Enable and disable flags cannot overlap"
        }
    }

    process {
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
}

<#
.SYNOPSIS
This enum defines the ACL revision levels that are used in Windows security descriptors.
.LINK
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
#>
enum AclRevision {
    # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL.
    # An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see MS-DTYP section
    # 2.4.4.1.
    ACL_REVISION = 0x00000002

    # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable 
    # only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
    ACL_REVISION_DS = 0x00000004
}

function Get-EmptyRawAcl {
    $revision = [AclRevision]::ACL_REVISION
    $capacity = 0
    return [System.Security.AccessControl.RawAcl]::new([int]$revision, $capacity)
}

function Reset-SecurityDescriptor {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor
    )

    process {
        $flagsToRemove = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited -bor `
                         [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected -bor `
                         [System.Security.AccessControl.ControlFlags]::SystemAclAutoInherited -bor `
                         [System.Security.AccessControl.ControlFlags]::SystemAclProtected -bor `
                         [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor `
                         [System.Security.AccessControl.ControlFlags]::SystemAclPresent
        
        $controlFlags = [int]$SecurityDescriptor.ControlFlags -band (-bnot [int]$flagsToRemove)

        if ($PSCmdlet.ShouldProcess("SecurityDescriptor", "Reset ControlFlags, DACL and SACL")) {
            $SecurityDescriptor.DiscretionaryAcl = Get-EmptyRawAcl
            $SecurityDescriptor.SystemAcl = Get-EmptyRawAcl
            $SecurityDescriptor.SetFlags($controlFlags)
        }
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
Standard rights for any type of securable object (including files and folders).
#>
enum GenericRights {
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
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

<#
.SYNOPSIS
Standard rights combinations for any type of securable object (including files and folders).

.LINK
https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
#>
enum StandardRightsCombination {
    # 2031616 is obtained via:
    #   [StandardRights]::DELETE -bor
    #   [StandardRights]::READ_CONTROL -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER -bor
    #   [StandardRights]::SYNCHRONIZE
    STANDARD_RIGHTS_ALL = 2031616
    STANDARD_RIGHTS_EXECUTE = [StandardRights]::READ_CONTROL
    STANDARD_RIGHTS_READ = [StandardRights]::READ_CONTROL
    # 983040 is obtained via:
    #   [StandardRights]::DELETE -bor
    #   [StandardRights]::READ_CONTROL -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER
    STANDARD_RIGHTS_REQUIRED = 983040
    STANDARD_RIGHTS_WRITE = [StandardRights]::READ_CONTROL
}

<#
.SYNOPSIS
This is a mapping of the generic rights to the specific rights for files and folders.

.LINK
https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
#>
enum FileGenericRightsMapping {
    # FILE_GENERIC_READ is defined as the following, which evaluates to 1179785:
    #
    #   [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #   [SpecificRights]::FILE_READ_DATA -bor
    #   [SpecificRights]::FILE_READ_EA -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_READ -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_READ = 1179785

    # FILE_GENERIC_WRITE is defined as the following, which evaluates to 1179926:
    #
    #   [SpecificRights]::FILE_APPEND_DATA -bor
    #   [SpecificRights]::FILE_WRITE_ATTRIBUTES -bor
    #   [SpecificRights]::FILE_WRITE_DATA -bor
    #   [SpecificRights]::FILE_WRITE_EA -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_WRITE -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_WRITE = 1179926

    # FILE_GENERIC_EXECUTE is defined as the following, which evaluates to 1179808:
    #   [SpecificRights]::FILE_EXECUTE -bor
    #   [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_EXECUTE -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_EXECUTE = 1179808

    # FILE_ALL_ACCESS is not documented, but in practice it's the same as FULL_ACCESS
    FILE_ALL_ACCESS = 2032127
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

    process {
        $controlFlagsHex = "0x{0:X}" -f [int]$descriptor.ControlFlags
        
        Write-Host "Owner: $($PSStyle.Foreground.Cyan)$($descriptor.Owner)$($PSStyle.Reset)"
        Write-Host "Group: $($PSStyle.Foreground.Cyan)$($descriptor.Group)$($PSStyle.Reset)"
        Write-Host "ControlFlags: $($PSStyle.Foreground.Cyan)$controlFlagsHex$($PSStyle.Reset) ($($descriptor.ControlFlags))"
        Write-Host "DiscretionaryAcl:"
        Write-Acl $descriptor.DiscretionaryAcl -indent 4
        Write-Host "SystemAcl:"
        Write-Acl $descriptor.SystemAcl -indent 4
    }
}

function Write-Acl {
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawAcl]$acl,

        [Parameter(Mandatory = $false)]
        [int]$indent = 0
    )

    begin {
        $spaces = " " * $indent
    }

    process {
        if ($acl -eq $null) {
            Write-Host "${spaces}Not present"
            return
        }

        Write-Host "${spaces}Revision:     $($($PSStyle.Foreground.Cyan))$($acl.Revision)$($PSStyle.Reset)"
        Write-Host "${spaces}BinaryLength: $($($PSStyle.Foreground.Cyan))$($acl.BinaryLength)$($PSStyle.Reset)"
        Write-Host "${spaces}AceCount:     $($($PSStyle.Foreground.Cyan))$($acl.Count)$($PSStyle.Reset)"
        $i = 0
        foreach ($ace in $acl) {
            Write-Host "${spaces}Ace $($PSStyle.Foreground.Green)${i}$($PSStyle.Reset):"
            Write-Ace $ace -indent ($indent + 4)
            $i++
        }
    }
}

function Write-Ace {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.AccessControl.GenericAce]$ace,

        [Parameter(Mandatory = $false)]
        [int]$indent = 0
    )

    begin {
        $spaces = " " * $indent
    }

    process {
        $aceTypeHex = "0x{0:X}" -f [int]$ace.AceType
        $aceSizeHex = "0x{0:X}" -f [int]$ace.BinaryLength
        $aceFlagsHex = "0x{0:X}" -f [int]$ace.AceFlags
        $accessMaskHex = "0x{0:X}" -f [int]$ace.AccessMask

        Write-Host "${spaces}Ace Sid:          $($PSStyle.Foreground.Cyan)$($ace.SecurityIdentifier)$($PSStyle.Reset)"
        Write-Host "${spaces}AceType:          $($PSStyle.Foreground.Cyan)$aceTypeHex$($PSStyle.Reset) ($($ace.AceType))"
        Write-Host "${spaces}AceSize:          $($PSStyle.Foreground.Cyan)$aceSizeHex$($PSStyle.Reset) ($($ace.BinaryLength))"
        Write-Host "${spaces}AceFlags:         $($PSStyle.Foreground.Cyan)$aceFlagsHex$($PSStyle.Reset) ($($ace.AceFlags))"
        Write-Host "${spaces}Access Mask:      $($PSStyle.Foreground.Cyan)$accessMaskHex$($PSStyle.Reset) ($($ace.AccessMask))"
        Write-AccessMask $ace.AccessMask -indent ($indent + 4)
    }
}

function Write-AccessMask {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$accessMask,

        [Parameter(Mandatory = $false)]
        [int]$indent = 0,

        [Parameter(Mandatory = $false)]
        [switch]$ShowFullList = $false
    )

    $spaces = " " * $indent
    $mask = [AccessMask]::new($accessMask)

    $checkmark = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2713", 16))
    $cross = [System.Char]::ConvertFromUtf32([System.Convert]::ToInt32("2717", 16))
    
    if ($ShowFullList) {
        Write-Host "${spaces}simplified list:"
    }
    
    # Write "basic permissions" first (e.g. composite rights like "Read", "Write", "Modify", etc.)
    $checkedValues = 0
    foreach ($key in [Enum]::GetValues([BasicPermissions])) {
        $value = $key.value__
        if ($mask.Has($value)) {
            $checkedValues = $checkedValues -bor $value
            Write-Host "${spaces}$($PSStyle.Foreground.Green)$checkmark$($PSStyle.Reset) $key"
        }
        else {
            Write-Host "${spaces}$($PSStyle.Foreground.Red)$cross$($PSStyle.Reset) $key"
        }
    }
    
    # Write if there are any permissions not covered by basic
    $remaining = [AccessMask]::new($accessMask)
    $remaining.Remove($checkedValues)
    if ($remaining.Value -ne 0) {
        # Check what known values remain, in addition to the values already checked above
        $allValues = [Enum]::GetValues([SpecificRights]) + [Enum]::GetValues([StandardRights]) + [Enum]::GetValues([GenericRights])
        $remainingValueList = $allValues | Where-Object { $remaining.Has($_.value__) }
        
        # If there are any bits not covered by the known permissions, add it to the list
        $remainingValueList | ForEach-Object { $remaining.Remove($_.value__) }
        if ($remaining.Value -ne 0) {
            $remainingValueList += [string]::Format("0x{0:X}", $remaining.Value)
        }

        $remainingString = $remainingValueList -join ", "
        Write-Host "${spaces}$($PSStyle.Foreground.Green)$checkmark$($PSStyle.Reset) SPECIAL_PERMISSIONS ($remainingString)"
    }
    else {
        Write-Host "${spaces}$($PSStyle.Foreground.Red)$cross$($PSStyle.Reset) $key SPECIAL_PERMISSIONS"
    }

    # Optionally write the full list of permissions bits
    if ($ShowFullList) {
        Write-Host "${spaces}full list:"
        foreach ($key in [Enum]::GetValues([SpecificRights]) + [Enum]::GetValues([StandardRights]) + [Enum]::GetValues([GenericRights])) {
            $value = $key.value__
            if ($mask.Has($value)) {
                Write-Host "${spaces}    ${key}"
                $mask.Remove($value)
            }
        }

        if ($mask.Value -ne 0) {
            $hex = "0x{0:X}" -f $mask.Value
            Write-Host "${spaces}    Others: $hex"
        }
    }
}

