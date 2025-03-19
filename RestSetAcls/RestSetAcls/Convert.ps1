function ConvertTo-SecurityDescriptor {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$InputDescriptor,

        [Parameter(Mandatory = $false)]
        [Alias("From")]
        [SecurityDescriptorFormat]$InputFormat = [SecurityDescriptorFormat]::Sddl
    )

    process {
        switch ($InputFormat) {
            "Sddl" {
                if ($InputDescriptor -isnot [string]) {
                    throw "Invalid input type. Expected string."
                }

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

                try {
                    return [System.Security.AccessControl.RawSecurityDescriptor]::new($InputDescriptor)
                }
                catch {
                    if ($_ -match "The SDDL string contains an invalid sid or a sid that cannot be translated") {
                        throw (
                            "Failed to convert SDDL to RawSecurityDescriptor.`n" +
                            "This may be due to the presence of domain-relative SIDs, such as " + 
                            "'LA', 'LG', 'CA', 'DA', 'DD', 'DU', 'DG', 'DC', 'SA', 'EA', 'PA', 'RS', 'ED' or 'RO'.`n" +
                            "Original error: $_"
                        )
                    }
                    else {
                        throw $_
                    }
                }
            }
            "Base64" {
                if ($InputDescriptor -isnot [string]) {
                    throw "Invalid input type. Expected string."
                }

                try {
                    $binary = [System.Convert]::FromBase64String($InputDescriptor)
                }
                catch {
                    throw "Invalid input object. Expected valid base64 string."
                }
                
                return [System.Security.AccessControl.RawSecurityDescriptor]::new($binary, 0)
            }
            "Binary" {
                if ($InputDescriptor -isnot [object[]]) {
                    throw "Invalid input type. Expected object[]."
                }
                return [System.Security.AccessControl.RawSecurityDescriptor]::new($InputDescriptor, 0)
            }
            "Raw" {
                if ($InputDescriptor -isnot [System.Security.AccessControl.RawSecurityDescriptor]) {
                    throw "Invalid input type. Expected RawSecurityDescriptor."
                }
                return $InputDescriptor
            }
            default {
                throw "Invalid input format. Expected Sddl, Base64, Binary or Raw."
            }
        }
    }
}

function ConvertFrom-SecurityDescriptor {
    [CmdletBinding()]
    [OutputType([string], [byte[]], [System.Security.AccessControl.RawSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.Security.AccessControl.RawSecurityDescriptor]$SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [Alias("To")]
        [SecurityDescriptorFormat]$OutputFormat = [SecurityDescriptorFormat]::Sddl
    )

    process {
        switch ($OutputFormat) {
            "Sddl" {
                return $SecurityDescriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
            }
            "Binary" {
                $binary = [byte[]]::new($SecurityDescriptor.BinaryLength)
                $SecurityDescriptor.GetBinaryForm($binary, 0)
                return $binary
            }
            "Base64" {
                $binary = [byte[]]::new($SecurityDescriptor.BinaryLength)
                $SecurityDescriptor.GetBinaryForm($binary, 0)
                return [System.Convert]::ToBase64String($binary)
            }
            "Raw" {
                return $SecurityDescriptor
            }
        }
    }
}

function Convert-SecurityDescriptor {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor], [string], [byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Alias("Input")]
        [object]$InputDescriptor,

        [Parameter(Mandatory = $true)]
        [Alias("From")]
        [SecurityDescriptorFormat]$InputFormat,

        [Parameter(Mandatory = $true)]
        [Alias("To")]
        [SecurityDescriptorFormat]$OutputFormat
    )

    process {
        $rawDescriptor = ConvertTo-SecurityDescriptor $InputDescriptor -InputFormat $InputFormat
        return ConvertFrom-SecurityDescriptor $rawDescriptor -OutputFormat $OutputFormat
    }
}