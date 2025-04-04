function Get-InferredAclFormat {
    [CmdletBinding()]
    [OutputType([SecurityDescriptorFormat])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$Acl
    )

    process {
        if ($Acl -is [string]) {
            $Acl = $Acl.Trim()

            if ($Acl -match "^[A-Za-z0-9+/=]+$") {
                return [SecurityDescriptorFormat]::Base64
            }
            
            if ($Acl.StartsWith("O:")) {
                return [SecurityDescriptorFormat]::Sddl
            }

            throw "Invalid input format. Expected SDDL or Base64."
        }

        if ($Acl -is [array]) {
            return [SecurityDescriptorFormat]::Binary
        }

        if ($Acl -is [System.Security.AccessControl.RawSecurityDescriptor]) {
            return [SecurityDescriptorFormat]::Raw
        }
        
        throw "Could not infer the format of the input. Expected SDDL, Base64, Binary or Raw."
    }
}

function ConvertTo-SecurityDescriptor {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [object]$InputDescriptor,

        [Parameter(Mandatory = $false)]
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
                    throw "Invalid input type. Expected string, got $($InputDescriptor.GetType().FullName)."
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
                if ($InputDescriptor -isnot [array]) {
                    throw "Invalid input type. Expected array, got $($InputDescriptor.GetType().FullName)."
                }
                return [System.Security.AccessControl.RawSecurityDescriptor]::new($InputDescriptor, 0)
            }
            "Raw" {
                if ($InputDescriptor -isnot [System.Security.AccessControl.RawSecurityDescriptor]) {
                    throw "Invalid input type. Expected RawSecurityDescriptor, got $($InputDescriptor.GetType().FullName)"
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
<#
    .SYNOPSIS
        Converts a security descriptor between different formats (Sddl, Base64, Binary, Raw).

    .DESCRIPTION
        This script provides functionality to convert a security descriptor from one format to another. 
        Supported formats include:
        - SDDL (Security Descriptor Definition Language)
        - Base64
        - Binary
        - Raw

        Security descriptors are used to define access control and permissions for resources. 
        This script is useful for scenarios where you need to translate security descriptors 
        into a format compatible with a specific system or API.

    .PARAMETER InputDescriptor
        The security descriptor value in the format specified by the `From` parameter.

    .PARAMETER From
        Specifies the format of the input security descriptor. 
        Accepted values: Sddl, Base64, Binary, Raw.

    .PARAMETER To
        Specifies the desired format for the output security descriptor. 
        Accepted values: Sddl, Base64, Binary, Raw.
    
    .EXAMPLE
        # Convert a security descriptor from SDDL to Base64
        Convert-SecurityDescriptor "O:BAG:BAD:(A;;FA;;;SY)" -From Sddl -To Base64
#>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor], [string], [byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Alias("Input")]
        [object]$InputDescriptor,

        [Parameter(Mandatory = $false)]
        [Alias("InputFormat")]
        [SecurityDescriptorFormat]$From,

        [Parameter(Mandatory = $true)]
        [Alias("OutputFormat")]
        [SecurityDescriptorFormat]$To
    )

    process {
        if ($null -eq $From) {
            try {
                $From = Get-InferredAclFormat $InputDescriptor
            }
            catch {
                throw "Could not infer the format of the input. Use -From to explicitly specify the format."
            }
        }

        if ($PSCmdlet.ShouldProcess($InputDescriptor, "Convert security descriptor from $From to $To")) {
            $rawDescriptor = ConvertTo-SecurityDescriptor $InputDescriptor -InputFormat $From
            return ConvertFrom-SecurityDescriptor $rawDescriptor -OutputFormat $To
        }
    }
}