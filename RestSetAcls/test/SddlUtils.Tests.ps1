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

    Describe "-Binary" {
        It "Should be able to parse valid binary" {
            $binary = @(
                # HEADER #
                0x01, # Revision
                0x00, # Sbz1
                0x00, 0xa0, # Control flags (SE_SELF_RELATIVE | SE_SACL_PROTECTED)
                0x14, 0x00, 0x00, 0x00, # OffsetOwner (20)
                0x24, 0x00, 0x00, 0x00, # OffsetGroup (36)
                0x00, 0x00, 0x00, 0x00, # OffsetSacl (0, no SACL)
                0x00, 0x00, 0x00, 0x00, # OffsetDacl (0, no DACL)
    
                # OWNER #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # SubAuthority 1 (544)
    
                # GROUP #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00  # SubAuthority 1 (544)
            )

            $descriptor = ConvertTo-SecurityDescriptor -Binary $binary
            $descriptor.Owner | Should -Be "S-1-5-32-544"
            $descriptor.Group | Should -Be "S-1-5-32-544"
            $descriptor.ControlFlags | Should -Be (
                [System.Security.AccessControl.ControlFlags]::SelfRelative -bor
                [System.Security.AccessControl.ControlFlags]::SystemAclProtected
            )
            $descriptor.DiscretionaryAcl | Should -BeNullOrEmpty
            $descriptor.SystemAcl | Should -BeNullOrEmpty
        }

        It "Should be able to parse valid binary with a DACL" {
            $binary = @(
                # HEADER #
                0x01, # Revision
                0x00, # Sbz1
                0x04, 0xa0, # Control flags (SE_SELF_RELATIVE | SE_SACL_PROTECTED | SE_DACL_PRESENT)
                0x14, 0x00, 0x00, 0x00, # OffsetOwner (20)
                0x24, 0x00, 0x00, 0x00, # OffsetGroup (36)
                0x00, 0x00, 0x00, 0x00, # OffsetSacl (0, no SACL)
                0x34, 0x00, 0x00, 0x00, # OffsetDacl (52)

                # OWNER #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # SubAuthority 1 (544)

                # GROUP #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # SubAuthority 1 (544)

                # DACL #
                0x02, # Revision
                0x00, # Sbz1
                0x34, 0x00, # AclSize (52)
                0x02, 0x00, # AclCount (2)
                0x00, 0x00, # Sbz2

                0x00, # ACE 0 type (ACCESS_ALLOWED_ACE_TYPE)
                0x00, # ACE 0 flags
                0x18, 0x00, # ACE 0 size (24)
                0xff, 0x01, 0x1f, 0x00, # ACE 0 mask (0x1F01FF aka FULL_CONTROL)
                0x01, # ACE 0 SID revision (1)
                0x02, # ACE 0 SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # ACE 0 SID IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # ACE 0 SID SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # ACE 0 SID SubAuthority 1 (544)

                0x00, # ACE 1 type (ACCESS_ALLOWED_ACE_TYPE)
                0x10, # ACE 1 flags (INHERITED_ACE)
                0x14, 0x00, # ACE 1 size (20)
                0xff, 0x01, 0x1f, 0x00, # ACE 1 mask (0x1F01FF aka FULL_CONTROL)
                0x01, # ACE 1 SID revision (1)
                0x01, # ACE 1 SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # ACE 1 SID IdentifierAuthority (5)
                0x12, 0x00, 0x00, 0x00 # ACE 1 SID SubAuthority 0 (18)
            )

            $descriptor = ConvertTo-SecurityDescriptor -Binary $binary
            $descriptor.Owner | Should -Be "S-1-5-32-544"
            $descriptor.Group | Should -Be "S-1-5-32-544"
            $descriptor.ControlFlags | Should -Be (
                [System.Security.AccessControl.ControlFlags]::SelfRelative -bor
                [System.Security.AccessControl.ControlFlags]::SystemAclProtected -bor
                [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent
            )
            $descriptor.DiscretionaryAcl.Count | Should -Be 2
            $descriptor.DiscretionaryAcl[0].AceType | Should -Be ([System.Security.AccessControl.AceType]::AccessAllowed)
            $descriptor.DiscretionaryAcl[0].AccessMask | Should -Be ([BasicPermissions]::FULL_CONTROL)
            $descriptor.DiscretionaryAcl[0].SecurityIdentifier | Should -Be "S-1-5-32-544"

            $descriptor.DiscretionaryAcl[1].AceType | Should -Be ([System.Security.AccessControl.AceType]::AccessAllowed)
            $descriptor.DiscretionaryAcl[1].AceFlags | Should -Be ([System.Security.AccessControl.AceFlags]::Inherited)
            $descriptor.DiscretionaryAcl[1].AccessMask | Should -Be ([BasicPermissions]::FULL_CONTROL)
            $descriptor.DiscretionaryAcl[1].SecurityIdentifier | Should -Be "S-1-5-18"

            $descriptor.SystemAcl | Should -BeNullOrEmpty
        }

        It "Should throw an error when parsing binary with invalid revision" {
            $binary = @(
                0xFF, # Revision -- this is invalid, revision should be 1
                0x00, # Sbz1
                0x00, 0xa0, # Control flags (SE_SELF_RELATIVE | SE_SACL_PROTECTED)
                0x14, 0x00, 0x00, 0x00, # OffsetOwner (20)
                0x24, 0x00, 0x00, 0x00, # OffsetGroup (36)
                0x00, 0x00, 0x00, 0x00, # OffsetSacl (0, no SACL)
                0x00, 0x00, 0x00, 0x00, # OffsetDacl (0, no DACL)
    
                # OWNER
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # SubAuthority 1 (544)
    
                # GROUP
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00  # SubAuthority 1 (544)
            )

            { ConvertTo-SecurityDescriptor -Binary $binary } | Should -Throw 
        }
    }

    Describe "-Base64" {
        It "Should be able to parse valid Base64" {
            $binary = @(
                # HEADER #
                0x01, # Revision
                0x00, # Sbz1
                0x00, 0xa0, # Control flags (SE_SELF_RELATIVE | SE_SACL_PROTECTED)
                0x14, 0x00, 0x00, 0x00, # OffsetOwner (20)
                0x24, 0x00, 0x00, 0x00, # OffsetGroup (36)
                0x00, 0x00, 0x00, 0x00, # OffsetSacl (0, no SACL)
                0x00, 0x00, 0x00, 0x00, # OffsetDacl (0, no DACL)
    
                # OWNER #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # SubAuthority 1 (544)
    
                # GROUP #
                0x01, # Revision (1)
                0x02, # SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00  # SubAuthority 1 (544)
            )

            $base64 = [System.Convert]::ToBase64String($binary)
            $descriptor = ConvertTo-SecurityDescriptor -Base64 $base64
            $descriptor.Owner | Should -Be "S-1-5-32-544"
            $descriptor.Group | Should -Be "S-1-5-32-544"
            $descriptor.ControlFlags | Should -Be (
                [System.Security.AccessControl.ControlFlags]::SelfRelative -bor
                [System.Security.AccessControl.ControlFlags]::SystemAclProtected
            )
            $descriptor.DiscretionaryAcl | Should -BeNullOrEmpty
            $descriptor.SystemAcl | Should -BeNullOrEmpty            
        }

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

    It "Should be able to convert SDDL to base64 and back with pipelines" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $base64 = ConvertTo-SecurityDescriptor -Sddl $sddl | ConvertFrom-SecurityDescriptor -OutputFormat Base64
        { [System.Convert]::FromBase64String($base64) } | Should -Not -Throw
        $newSddl = ConvertTo-SecurityDescriptor -Base64 $base64 | ConvertFrom-SecurityDescriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }

    It "Should be able to return binary" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
        $binary = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Binary
        Should -ActualValue $binary -BeOfType [System.Object[]] # should be an array
        $binary | Should -BeOfType [byte] # each element should be a byte
    }

    It "Should be able to return valid base64" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
        $base64 = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Base64
        $base64 | Should -BeOfType [string]
        { [System.Convert]::FromBase64String($base64) } | Should -Not -Throw
    }

    It "Should return equivalent base64 and binary" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
        $binary = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Binary
        $base64 = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Base64
        $binaryFromBase64 = [System.Convert]::FromBase64String($base64)
        $binary | Should -Be $binaryFromBase64
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
