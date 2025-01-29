BeforeAll {
    . $PSScriptRoot/../RestSetAcls/SddlUtils.ps1
}

Describe "ConvertTo-SecurityDescriptor" {
    Describe "-Sddl" {
        It "Should be able to parse valid SDDL" {
            $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
            $descriptor.DiscretionaryAcl.Count | Should -Be 3
        }

        It "Should be able to parse complex but valid SDDL" {
            $sddl = "O:BAG:BAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(A;;RPWPCCDCLCRCWOWDSDSW;;;BA)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;6da8a4ff-0e52-11d0-a286-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCRC;;;AU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
            $descriptor.Owner | Should -Be "S-1-5-32-544"
            $descriptor.Group | Should -Be "S-1-5-32-544"
            $descriptor.DiscretionaryAcl.Count | Should -Be 7
            $descriptor.SystemAcl.Count | Should -Be 1
        }
    
        It "Should parse inheritance and propagation flags" {
            $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            $descriptor.DiscretionaryAcl.Count | Should -Be 2
            $descriptor.DiscretionaryAcl[0].InheritanceFlags | Should -Be "ContainerInherit, ObjectInherit"
            $descriptor.DiscretionaryAcl[0].PropagationFlags | Should -Be "None"
            $descriptor.DiscretionaryAcl[1].InheritanceFlags | Should -Be "None"
            $descriptor.DiscretionaryAcl[1].PropagationFlags | Should -Be "NoPropagateInherit, InheritOnly"
        }
    
        It "Should be able to parse SDDL with D:NO_ACCESS_CONTROL" {
            $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:NO_ACCESS_CONTROL"
            $descriptor.DiscretionaryAcl.Count | Should -Be 0
        }
    
        It "Should be able to parse SDDL without a DACL" {
            $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SY"
            $descriptor.DiscretionaryAcl.Count | Should -Be 0
        }
        
        It "Should throw an error when the SDDL contains domain-relative SIDs" {
            { ConvertTo-SecurityDescriptor -Sddl "O:DAB:SYD:NO_ACCESS_CONTROL" } | Should -Throw
        }

        It "Should throw an error when parsing invalid SDDL" {
            { ConvertTo-SecurityDescriptor -Sddl "not valid SDDL :)" } | Should -Throw
        }
    }

    Describe "-Base64" {
        It "Should throw an error when parsing invalid Base64" {
            { ConvertTo-SecurityDescriptor -Base64 "not valid Base64 :)" } | Should -Throw
        }
    }
}

Describe "ConvertFrom-SecurityDescriptor" {
    It "Should return the same SDDL" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }
}

Describe "Get-AllAceFlagsMatch" {
    It "Should return true when all -EnabledFlags are present" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;OICINP;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
        $result | Should -Be $true
    }

    It "Should return false when some -EnabledFlags are missing" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OI;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "ContainerInherit, ObjectInherit" -DisabledFlags "None"
        $result | Should -Be $false
    }

    It "Should return true when all -DisabledFlags are missing" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)(A;NP;0x1301bf;;;AU)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "ContainerInherit, ObjectInherit"
        $result | Should -Be $true
    }

    It "Should return false when some -DisabledFlags are present" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;NP;0x1201bf;;;WD)"
        $result = Get-AllAceFlagsMatch -SecurityDescriptor $descriptor -EnabledFlags "None" -DisabledFlags "NoPropagateInherit"
        $result | Should -Be $false
    }
}

Describe "Set-AceFlags" {
    It "Should add -EnableFlags if they are not yet set" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;OI;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICINPIO;0x1201bf;;;WD)"
    }

    It "Should not change anything if -EnableFlags are already set" {
        $sddl = "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
        $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "None"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }

    It "Should not change the value of ID flag" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;ID;0x1301bf;;;WD)(A;OIID;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "ContainerInherit, ObjectInherit" -DisableFlags "NoPropagateInherit, InheritOnly"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;OICIID;0x1301bf;;;WD)(A;OICIID;0x1201bf;;;WD)"
    }

    It "Should remove -DisableFlags if they are set" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;OICINPIO;0x1301bf;;;WD)(A;OICI;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;;0x1201bf;;;WD)"
    }

    It "Should not change anything if -DisableFlags are already unset" {
        $descriptor = ConvertTo-SecurityDescriptor -Sddl "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
        Set-AceFlags -SecurityDescriptor $descriptor -EnableFlags "None" -DisableFlags "ContainerInherit, ObjectInherit"
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be "O:SYG:SYD:AI(A;NPIO;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
    }
}
