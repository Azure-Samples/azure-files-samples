@{
    # Exclude a bunch of things for now. We can iteratively remove these as we clean up the code.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSAvoidTrailingWhitespace'
    )

    Rules = @{
        # Ensure we are using PowerShell syntax that is compatible
        # across multiple versions of PowerShell.
        PSUseCompatibleSyntax = @{
            Enable = $true
            
            # List the targeted versions of PowerShell here
            TargetVersions = @(
                '5.1',
                '7.0'
            )
        }

        PSUseCompatibleCommands = @{
            Enable = $true

            # Lists the PowerShell platforms we want to check compatibility with
            TargetProfiles = @(
                # PowerShell 7.0 on Windows 10.0.14393 
                'win-8_x64_10.0.14393.0_7.0.0_x64_3.1.2_core'
            )
        }
    }
}