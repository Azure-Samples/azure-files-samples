# This file tests the private functions in RestSetAcls.
# Private means functions that are not in FunctionsToExport in the module manifest.

BeforeAll {
    . $PSScriptRoot/../../RestSetAcls/Enumerations.ps1
    . $PSScriptRoot/../../RestSetAcls/Convert.ps1
    . $PSScriptRoot/../../RestSetAcls/SddlUtils.ps1
}

Describe "Get-AllAceFlagsMatch" {
    It "Should return true when all -EnabledFlags are present" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINP;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
        $result | Should -Be $true
    }

    It "Should be able to process multiple inputs from pipeline" {
        $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINP;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
        $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(D;OICINP;0x1301bf;;;WD)(D;OICIID;0x1201bf;;;WD)"
        $descriptors = @($descriptor1, $descriptor2)
        
        $results = $descriptors | Get-AllAceFlagsMatch -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"

        $results | Should -Be @($true, $true)        
    }

    It "Should return false when some -EnabledFlags are missing" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OI;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
        $result | Should -Be $false
    }

    It "Should return true when all -DisabledFlags are missing" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)(A;NP;0x1301bf;;;AU)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "ContainerInherit, ObjectInherit"
        $result | Should -Be $true
    }

    It "Should return false when some -DisabledFlags are present" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NP;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "NoPropagateInherit"
        $result | Should -Be $false
    }
}

Describe "Set-AceFlags" {
    It "Should add -EnableFlags if they are not yet set" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OI;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICINPIO;0x1201bf;;;WD)"
    }

    It "Should not change anything if -EnableFlags are already set" {
        $sddl = "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
        $descriptor = ConvertTo-SecurityDescriptor $sddl
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }

    It "Should not change the value of ID flag" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;ID;0x1301bf;;;WD)(A;OIID;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, InheritOnly"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;OICIID;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
    }

    It "Should remove -DisableFlags if they are set" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINPIO;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;;0x1201bf;;;WD)"
    }

    It "Should not change anything if -DisableFlags are already unset" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
    }

    It "Should process multiple items from input pipeline" {
        $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;IO;0x1201bf;;;WD)"
        
        $descriptors = @($descriptor1, $descriptor2)
        $descriptors | Set-AceFlags -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit" `
        
        $results = $descriptors | ConvertFrom-SecurityDescriptor -OutputFormat Sddl
        $results | Should -Be $( "O:SYG:SYD:AI(A;OICIIO;0x1301bf;;;WD)(A;OICIIO;0x1201bf;;;WD)", "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICIIO;0x1201bf;;;WD)" )
    }

    It "Should throw an error if EnableFlags and DisableFlags overlap" {
        $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        { Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, ContainerInherit" } | Should -Throw
    }

    It "Should throw an error if EnableFlags and DisableFlags overlap, when getting input from pipeline" {
        $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;IO;0x1201bf;;;WD)"
        $descriptors = @($descriptor1, $descriptor2)
        { $descriptors | Set-AceFlags -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, ContainerInherit" } | Should -Throw
    }
}
