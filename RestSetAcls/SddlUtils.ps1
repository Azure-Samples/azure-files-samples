function ConvertTo-RawSecurityDescriptor {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$sddl
    )
    
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

function ConvertFrom-RawSecurityDescriptor {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$descriptor
    )
    return $descriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

function Get-AllAceFlagsMatch {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.AceFlags]$EnabledFlags,

        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.AceFlags]$DisabledFlags
    )

    foreach ($ace in $SecurityDescriptor.DiscretionaryAcl) {
        $hasAllBitsFromEnabledFlags = ($ace.AceFlags -band $EnabledFlags) -eq $EnabledFlags
        $hasNoBitsFromDisabledFlags = ($ace.AceFlags -band $DisabledFlags) -eq 0
        if (-not ($hasAllBitsFromEnabledFlags -and $hasNoBitsFromDisabledFlags)) {
            return $false
        }
    }

    return $true
}

function Set-AceFlags {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,
        
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.AceFlags]$EnableFlags,

        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.AceFlags]$DisableFlags
    )

    if ($EnableFlags -band $DisableFlags) {
        throw "Enable and disable flags cannot overlap"
    }

    # Create new ACEs with updated flags
    $newAces = $SecurityDescriptor.DiscretionaryAcl | ForEach-Object {
        $aceFlags = ($_.AceFlags -bor $EnableFlags) -band (-bnot $DisableFlags)

        if ($_.GetType().Name -eq "CommonAce") {
            [System.Security.AccessControl.CommonAce]::new(
                $aceFlags,
                $_.AceQualifier,
                $_.AccessMask,
                $_.SecurityIdentifier,
                $_.IsCallback,
                $_.GetOpaque())
        } else {
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