# This file tests the private functions in RestSetAcls.
# Private means functions that are not in FunctionsToExport in the module manifest.

BeforeAll {
    Import-Module $PSScriptRoot/../../RestSetAcls/RestSetAcls.psd1 -Force
}

Describe "Get-AceFlagsFromInheritanceAndPropagation" {
    It "Should return None when both flags are None" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "None" -PropagationFlags "None"
            $result | Should -Be ([System.Security.AccessControl.AceFlags]::None)
        }
    }

    It "Should return ContainerInherit when InheritanceFlags is ContainerInherit" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ContainerInherit" -PropagationFlags "None"
            $result | Should -Be ([System.Security.AccessControl.AceFlags]::ContainerInherit)
        }
    }

    It "Should return ObjectInherit when InheritanceFlags is ObjectInherit" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ObjectInherit" -PropagationFlags "None"
            $result | Should -Be ([System.Security.AccessControl.AceFlags]::ObjectInherit)
        }
    }

    It "Should return ContainerInherit and ObjectInherit when InheritanceFlags has both" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ContainerInherit, ObjectInherit" -PropagationFlags "None"
            $expected = [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor [int][System.Security.AccessControl.AceFlags]::ObjectInherit
            $result | Should -Be $expected
        }
    }

    It "Should return InheritOnly when PropagationFlags is InheritOnly" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "None" -PropagationFlags "InheritOnly"
            $result | Should -Be ([System.Security.AccessControl.AceFlags]::InheritOnly)
        }
    }

    It "Should return NoPropagateInherit when PropagationFlags is NoPropagateInherit" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "None" -PropagationFlags "NoPropagateInherit"
            $result | Should -Be ([System.Security.AccessControl.AceFlags]::NoPropagateInherit)
        }
    }

    It "Should return InheritOnly and NoPropagateInherit when PropagationFlags has both" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "None" -PropagationFlags "InheritOnly, NoPropagateInherit"
            $expected = [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
            $result | Should -Be $expected
        }
    }

    It "Should combine all flags when both InheritanceFlags and PropagationFlags are set" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ContainerInherit, ObjectInherit" -PropagationFlags "InheritOnly, NoPropagateInherit"
            $expected = [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor 
                    [int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor 
                    [int][System.Security.AccessControl.AceFlags]::InheritOnly -bor 
                    [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
            $result | Should -Be $expected
        }
    }

    It "Should handle mixed combinations correctly" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ContainerInherit" -PropagationFlags "InheritOnly"
            $expected = [int][System.Security.AccessControl.AceFlags]::ContainerInherit -bor [int][System.Security.AccessControl.AceFlags]::InheritOnly
            $result | Should -Be $expected
        }
    }

    It "Should handle another mixed combination correctly" {
        InModuleScope RestSetAcls {
            $result = Get-AceFlagsFromInheritanceAndPropagation -InheritanceFlags "ObjectInherit" -PropagationFlags "NoPropagateInherit"
            $expected = [int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor [int][System.Security.AccessControl.AceFlags]::NoPropagateInherit
            $result | Should -Be $expected
        }
    }
}

Describe "Get-AllAceFlagsMatch" {
    It "Should return true when all -EnabledFlags are present" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINP;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
            $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
            $result | Should -Be $true
        }
    }

    It "Should be able to process multiple inputs from pipeline" {
        InModuleScope RestSetAcls {
            $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINP;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
            $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(D;OICINP;0x1301bf;;;WD)(D;OICIID;0x1201bf;;;WD)"
            $descriptors = @($descriptor1, $descriptor2)
            
            $results = $descriptors | Get-AllAceFlagsMatch -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"

            $results | Should -Be @($true, $true)
        }
    }

    It "Should return false when some -EnabledFlags are missing" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OI;0x1201bf;;;WD)"
            $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
            $result | Should -Be $false
        }
    }

    It "Should return true when all -DisabledFlags are missing" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)(A;NP;0x1301bf;;;AU)"
            $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "ContainerInherit, ObjectInherit"
            $result | Should -Be $true
        }
    }

    It "Should return false when some -DisabledFlags are present" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NP;0x1201bf;;;WD)"
            $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "NoPropagateInherit"
            $result | Should -Be $false
        }
    }
}

Describe "Set-AceFlags" {
    It "Should add -EnableFlags if they are not yet set" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OI;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
            $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
            $newSddl | Should -Be "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICINPIO;0x1201bf;;;WD)"
        }
    }

    It "Should not change anything if -EnableFlags are already set" {
        InModuleScope RestSetAcls {
            $sddl = "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
            $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
            $newSddl | Should -Be $sddl
        }
    }

    It "Should not change the value of ID flag" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;ID;0x1301bf;;;WD)(A;OIID;0x1201bf;;;WD)"
            Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, InheritOnly"
            $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
            $newSddl | Should -Be "O:SYG:SYD:AI(A;OICIID;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
        }
    }

    It "Should remove -DisableFlags if they are set" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;OICINPIO;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
            Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
            $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
            $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;;0x1201bf;;;WD)"
        }
    }

    It "Should not change anything if -DisableFlags are already unset" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
            $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
            $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        }
    }

    It "Should process multiple items from input pipeline" {
        InModuleScope RestSetAcls {
            $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;IO;0x1201bf;;;WD)"
            
            $descriptors = @($descriptor1, $descriptor2)
            $descriptors | Set-AceFlags -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit" `
            
            $results = $descriptors | ConvertFrom-SecurityDescriptor -OutputFormat Sddl
            $results | Should -Be $( "O:SYG:SYD:AI(A;OICIIO;0x1301bf;;;WD)(A;OICIIO;0x1201bf;;;WD)", "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICIIO;0x1201bf;;;WD)" )
        }
    }

    It "Should throw an error if EnableFlags and DisableFlags overlap" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            { Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, ContainerInherit" } | Should -Throw
        }
    }

    It "Should throw an error if EnableFlags and DisableFlags overlap, when getting input from pipeline" {
        InModuleScope RestSetAcls {
            $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;IO;0x1201bf;;;WD)"
            $descriptors = @($descriptor1, $descriptor2)
            { $descriptors | Set-AceFlags -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, ContainerInherit" } | Should -Throw
        }
    }
}

Describe "Reset-SecurityDescriptor" {
    It "Should reset ControlFlags" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)"
            # Verify the descriptor has non-zero ControlFlags initially
            $descriptor.ControlFlags | Should -Not -Be 0
            
            Reset-SecurityDescriptor -SecurityDescriptor $descriptor
            
            # Verify ControlFlags was reset to 0
            $expected = [System.Security.AccessControl.ControlFlags]::SelfRelative
            $descriptor.ControlFlags | Should -Be $expected
        }
    }

    It "Should reset DiscretionaryAcl to an empty ACL" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;;0x1201bf;;;WD)"
            # Verify the descriptor has non-empty DiscretionaryAcl initially
            $descriptor.DiscretionaryAcl.Count | Should -Be 2
            
            Reset-SecurityDescriptor -SecurityDescriptor $descriptor
            
            # Verify DiscretionaryAcl was reset to empty
            $descriptor.DiscretionaryAcl.Count | Should -Be 0
        }
    }

    It "Should reset SystemAcl to an empty ACL" {
        InModuleScope RestSetAcls {
            # Create a descriptor with a SystemAcl (using S: for the SACL in SDDL)
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AIS:(AU;SAIO;0x1301bf;;;WD)"
            # Verify the descriptor has a non-empty SystemAcl initially
            $descriptor.SystemAcl.Count | Should -Not -Be 0
            
            Reset-SecurityDescriptor -SecurityDescriptor $descriptor
            
            # Verify SystemAcl was reset to empty
            $descriptor.SystemAcl.Count | Should -Be 0
        }
    }

    It "Should process multiple items from input pipeline" {
        InModuleScope RestSetAcls {
            $descriptor1 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            $descriptor2 = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;IO;0x1201bf;;;WD)"
            $descriptors = @($descriptor1, $descriptor2)
            
            $descriptors | Reset-SecurityDescriptor
            
            # Verify all descriptors were reset
            $expected = [System.Security.AccessControl.ControlFlags]::SelfRelative

            $descriptor1.ControlFlags | Should -Be $expected
            $descriptor1.DiscretionaryAcl.Count | Should -Be 0
            $descriptor1.SystemAcl.Count | Should -Be 0
            
            $descriptor2.ControlFlags | Should -Be $expected
            $descriptor2.DiscretionaryAcl.Count | Should -Be 0
            $descriptor2.SystemAcl.Count | Should -Be 0
        }
    }
    
    It "Should maintain owner and group information" {
        InModuleScope RestSetAcls {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)"
            $ownerBefore = $descriptor.Owner
            $groupBefore = $descriptor.Group
            
            Reset-SecurityDescriptor -SecurityDescriptor $descriptor
            
            # Verify owner and group weren't changed
            $descriptor.Owner | Should -Be $ownerBefore
            $descriptor.Group | Should -Be $groupBefore
        }
    }
}
