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

        PSUseCompatibleTypes = @{
            Enable = $true
             # Lists the PowerShell platforms we want to check compatibility with
             # See: https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/rules/usecompatibletypes?view=ps-modules
             TargetProfiles = @(
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework', # PowerShell 5.1 on Windows Server 2016
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', # PowerShell 5.1 on Windows Server 2019
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework', # PowerShell 5.1 on Windows 10 Pro
                'win-8_x64_10.0.14393.0_6.2.4_x64_4.0.30319.42000_core', # PowerShell 6.2 on Windows 10.0.14393
                'win-8_x64_10.0.14393.0_7.0.0_x64_3.1.2_core' # PowerShell 7.0 on Windows 10.0.14393 
            )
        }
    }
}