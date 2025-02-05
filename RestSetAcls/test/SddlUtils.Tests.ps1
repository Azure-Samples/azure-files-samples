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

        It "Should be able to parse SDDL using every known access mask shorthand" -ForEach @(
            # Specific rights for "Directory Objects" (Active Directory objects)
            @{ AccessRight = "CC"; Expected = 0x001 },
            @{ AccessRight = "DC"; Expected = 0x002 },
            @{ AccessRight = "LC"; Expected = 0x004 },
            @{ AccessRight = "SW"; Expected = 0x008 },
            @{ AccessRight = "RP"; Expected = 0x010 },
            @{ AccessRight = "WP"; Expected = 0x020 },
            @{ AccessRight = "DT"; Expected = 0x040 },
            @{ AccessRight = "LO"; Expected = 0x080 },
            @{ AccessRight = "CR"; Expected = 0x100 }
            # Specific rights for Registry Keys
            @{ AccessRight = "KA"; Expected = 0x000F003F },
            @{ AccessRight = "KR"; Expected = 0x00020019 },
            @{ AccessRight = "KX"; Expected = 0x00020019 },
            @{ AccessRight = "KW"; Expected = 0x00020006 },
            # Specific rights for File System Objects (files/directories)
            @{ AccessRight = "FA"; Expected = 0x001F01FF },
            @{ AccessRight = "FX"; Expected = 0x001200A0 },
            @{ AccessRight = "FW"; Expected = 0x00120116 },
            @{ AccessRight = "FR"; Expected = 0x00120089 }
        ) {
            #
            # The [MS-DTYP][1] doc says that e.g. CC means "Create Child", and is applicable to *directory objects*.
            # Note that here, "directory object" means *Active Directory objects*, not file system objects.
            # It also says that e.g. KR means "Key Read", and is applicable to *registry keys*.
            #
            # Therefore, in theory, we should not apply CC or KR to file system objects. But Windows does not enforce this.
            # See e.g. [C++ API][2] (which doesn't have a param for object type), or see [.NET SDK implementation][3].
            # 
            # [1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
            # [2]: https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptora
            # [3]: https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.AccessControl/src/System/Security/AccessControl/SecurityDescriptor.cs
            #
            $sddl = "O:SYG:SYD:(A;;${AccessRight};;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
            
            $descriptor.DiscretionaryAcl.Count | Should -Be 1
            $mask = [int]$descriptor.DiscretionaryAcl[0].AccessMask
            $mask | Should -Be $Expected -Because "Expected access mask for $sddl to be $expected, but got $mask"
        }

        It "Should be able to parse SDDL using literal access mask hex values" -ForEach @(
            @{ AccessRight = "0x1"; Expected = 0x1 },
            @{ AccessRight = "0x2a"; Expected = 0x2A },
            @{ AccessRight = "0xAbCd"; Expected = 0xABCD },
            @{ AccessRight = "0x1F01FF"; Expected = 0x1F01FF },
            @{ AccessRight = "0x12345678"; Expected = 0x12345678 }
        ) {
            $sddl = "O:SYG:SYD:(A;;${AccessRight};;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor -Sddl $sddl
            
            $descriptor.DiscretionaryAcl.Count | Should -Be 1
            $mask = [int]$descriptor.DiscretionaryAcl[0].AccessMask
            $mask | Should -Be $Expected -Because "Expected access mask for $sddl to be $expected, but got $mask"
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

        It "Should be able to parse valid binary with a DACL containing multiple Allow ACEs" {
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
                0x38, 0x00, # AclSize (56)
                0x02, 0x00, # AclCount (2)
                0x00, 0x00, # Sbz2

                0x00, # ACE 0 type (ACCESS_ALLOWED_ACE_TYPE)
                0x00, # ACE 0 flags
                0x18, 0x00, # ACE 0 size (24)
                0x16, 0x01, 0x12, 0x00, # ACE 0 mask (0x00120116 aka SDDL "FW")
                0x01, # ACE 0 SID revision (1)
                0x02, # ACE 0 SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # ACE 0 SID IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # ACE 0 SID SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00, # ACE 0 SID SubAuthority 1 (544)

                0x00, # ACE 1 type (ACCESS_ALLOWED_ACE_TYPE)
                0x00, # ACE 1 flags
                0x18, 0x00, # ACE 1 size (24)
                0x89, 0x00, 0x12, 0x00, # ACE 1 mask (0x00120089 aka SDDL "FR")
                0x01, # ACE 1 SID revision (1)
                0x02, # ACE 1 SubAuthorityCount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x05, # ACE 1 SID IdentifierAuthority (5)
                0x20, 0x00, 0x00, 0x00, # ACE 1 SID SubAuthority 0 (32)
                0x20, 0x02, 0x00, 0x00 #  ACE 1 SID SubAuthority 1 (544)
            )

            ConvertTo-SecurityDescriptor -Binary $binary `
                | ConvertFrom-SecurityDescriptor -OutputFormat Sddl `
                | Should -Be "O:BAG:BAD:(A;;FW;;;BA)(A;;FR;;;BA)"
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
