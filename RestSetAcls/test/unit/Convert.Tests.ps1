BeforeAll {
    . $PSScriptRoot/../../RestSetAcls/Enumerations.ps1 -Force
    . $PSScriptRoot/../../RestSetAcls/Convert.ps1
    . $PSScriptRoot/../../RestSetAcls/SddlUtils.ps1
}

Describe "Convert-SecurityDescriptor" {
    BeforeAll {
        # Set up test values of equivalent permissions
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $base64 = "AQAEhBQAAAAgAAAAAAAAACwAAAABAQAAAAAABRIAAAABAQAAAAAABRIAAAACAEQAAwAAAAAAFAC/ARMAAQEAAAAAAAEAAAAAABAUAL8BEgABAQAAAAAAAQAAAAAAABQA/wETAAEBAAAAAAAFCwAAAA=="
        [byte[]]$binary = @(
            1, 0, 4, 132, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 2, 0, 68, 0, 3, 0, 0, 0, 0, 0, 20, 0, 191, 1, 19, 0, 1, 1, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 16, 20, 0, 191, 1, 18, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 20, 0, 255, 1, 19, 0, 1,
            1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0
        )
        $rawSecurityDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        $folderSecurityDescriptor = [System.Security.AccessControl.CommonSecurityDescriptor]::new($true, $false, $sddl)
        $fileSecurityDescriptor = [System.Security.AccessControl.CommonSecurityDescriptor]::new($true, $false, $sddl)

        function Get-TestInputValue([SecurityDescriptorFormat]$format) {
            switch ($format) {
                'Sddl' { return $sddl }
                'Base64' { return $base64 }
                'Binary' { return $binary }
                'Raw' { return $rawSecurityDescriptor }
                'FileAcl' { return $fileSecurityDescriptor }
                'FolderAcl' { return $folderSecurityDescriptor }
            }
        }

        function Assert-OutputIsCorrect {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Format,
                
                [Parameter(Mandatory = $true)]
                [object]$outputValue
            )

            if ($format -eq 'Sddl') {
                $outputValue | Should -BeOfType [string]
                $outputValue | Should -Be $sddl
            }
            elseif ($format -eq 'Base64') {
                $outputValue | Should -BeOfType [string]
                $outputValue | Should -Be $base64
            }
            elseif ($format -eq 'Binary') {
                Should -ActualValue $outputValue -BeOfType [array]
                $outputValue | Should -Be $binary
            }
            elseif ($format -eq 'Raw' -or $format -eq 'FileAcl' -or $format -eq 'FolderAcl') {
                $expectedType = switch ($format) {
                    'Raw' { [System.Security.AccessControl.RawSecurityDescriptor] }
                    default { [System.Security.AccessControl.CommonSecurityDescriptor] }
                }
                $outputValue | Should -BeOfType $expectedType

                $sd = $outputValue -as [System.Security.AccessControl.GenericSecurityDescriptor]
                $sd.BinaryLength | Should -Be $binary.Length
                $bytes = New-Object byte[] $sd.BinaryLength
                $sd.GetBinaryForm($bytes, 0)
            }
            else {
                throw "Unknown format: $format"
            }
        }
    }

    Describe "-From -To" {
        It "Should convert from <from> to <to>" -ForEach @(
            @{ From = "Sddl";   To = "Sddl"      },
            @{ From = "Sddl";   To = "Base64"    },
            @{ From = "Sddl";   To = "Binary"    },
            @{ From = "Sddl";   To = "Raw"       },
            @{ From = "Sddl";   To = "FileAcl"   },
            @{ From = "Sddl";   To = "FolderAcl" },
            @{ From = "Base64"; To = "Sddl"      },
            @{ From = "Base64"; To = "Base64"    },
            @{ From = "Base64"; To = "Binary"    },
            @{ From = "Base64"; To = "Raw"       },
            @{ From = "Base64"; To = "FileAcl"   },
            @{ From = "Base64"; To = "FolderAcl" },
            @{ From = "Binary"; To = "Sddl"      },
            @{ From = "Binary"; To = "Base64"    },
            @{ From = "Binary"; To = "Binary"    },
            @{ From = "Binary"; To = "Raw"       },
            @{ From = "Binary"; To = "FileAcl"   },
            @{ From = "Binary"; To = "FolderAcl" },
            @{ From = "Raw";    To = "Sddl"      },
            @{ From = "Raw";    To = "Base64"    },
            @{ From = "Raw";    To = "Binary"    },
            @{ From = "Raw";    To = "Raw"       },
            @{ From = "Raw";    To = "FileAcl"   },
            @{ From = "Raw";    To = "FolderAcl" }
        ) {
            param ($From, $To)
            $inputValue = Get-TestInputValue $From
            
            $outputValue = Convert-SecurityDescriptor $inputValue -From $From -To $To

            Assert-OutputIsCorrect -Format $To -OutputValue $outputValue   
        }

        It "Should throw an error for null -From input format" {
            { Convert-SecurityDescriptor $sddl -From $null -To Sddl } | Should -Throw
        }

        It "Should throw an error for invalid -From input format" {
            { Convert-SecurityDescriptor $sddl -From "InvalidFormat" -To Sddl } | Should -Throw
        }

        It "Should throw an error for invalid -To output format" {
            { Convert-SecurityDescriptor $sddl -From Sddl -To "InvalidFormat" } | Should -Throw
        }

        It "Should process multiple inputs from pipeline" {
            $sddl1 = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)"
            $sddl2 = "O:SYG:SYD:AI(A;;0x1201bf;;;AU)"
            $sddls = @($sddl1, $sddl2)
            $results = $sddls | Convert-SecurityDescriptor -From Sddl -To Base64
            $results | Should -BeOfType [string]
            $results.Count | Should -Be 2
        }

        It "Should throw an error when -InputDescriptor type doesn't match -From type" {
            { Convert-SecurityDescriptor $sddl -From Binary -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $sddl -From Base64 -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $sddl -From Raw -To Raw } | Should -Throw
    
            { Convert-SecurityDescriptor $binary -From Sddl -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $binary -From Base64 -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $binary -From Raw -To Raw } | Should -Throw
    
            { Convert-SecurityDescriptor $base64 -From Sddl -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $base64 -From Binary -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $base64 -From Raw -To Raw } | Should -Throw
    
            { Convert-SecurityDescriptor $rawSecurityDescriptor -From Sddl -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $rawSecurityDescriptor -From Base64 -To Raw } | Should -Throw
            { Convert-SecurityDescriptor $rawSecurityDescriptor -From Binary -To Raw } | Should -Throw        
        }
    }

    Describe "-To" {
        It "Should convert from <from> to <to>" -ForEach @(
            @{ From = "Sddl";   To = "Sddl"      },
            @{ From = "Sddl";   To = "Base64"    },
            @{ From = "Sddl";   To = "Binary"    },
            @{ From = "Sddl";   To = "Raw"       },
            @{ From = "Sddl";   To = "FileAcl"   },
            @{ From = "Sddl";   To = "FolderAcl" },
            @{ From = "Base64"; To = "Sddl"      },
            @{ From = "Base64"; To = "Base64"    },
            @{ From = "Base64"; To = "Binary"    },
            @{ From = "Base64"; To = "Raw"       },
            @{ From = "Base64"; To = "FileAcl"   },
            @{ From = "Base64"; To = "FolderAcl" },
            @{ From = "Binary"; To = "Sddl"      },
            @{ From = "Binary"; To = "Base64"    },
            @{ From = "Binary"; To = "Binary"    },
            @{ From = "Binary"; To = "Raw"       },
            @{ From = "Binary"; To = "FileAcl"   },
            @{ From = "Binary"; To = "FolderAcl" },
            @{ From = "Raw";    To = "Sddl"      },
            @{ From = "Raw";    To = "Base64"    },
            @{ From = "Raw";    To = "Binary"    },
            @{ From = "Raw";    To = "Raw"       },
            @{ From = "Raw";    To = "FileAcl"   },
            @{ From = "Raw";    To = "FolderAcl" }
        ) {
            param ($From, $To)
            $inputValue = Get-TestInputValue $From

            $outputValue = Convert-SecurityDescriptor $inputValue -To $To
            
            Assert-OutputIsCorrect -Format $To -OutputValue $outputValue
        }

        It "Should throw an error for invalid -To output format" {
            { Convert-SecurityDescriptor $sddl -To "InvalidFormat" } | Should -Throw
        }

        It "Should process multiple inputs from pipeline" {
            $sddl1 = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)"
            $sddl2 = "O:SYG:SYD:AI(A;;0x1201bf;;;AU)"
            $sddls = @($sddl1, $sddl2)
            $results = $sddls | Convert-SecurityDescriptor -To Base64
            $results | Should -BeOfType [string]
            $results.Count | Should -Be 2
        }
    }
}

Describe "ConvertTo-SecurityDescriptor" {
    Describe "Sddl" {
        It "Should be able to parse valid SDDL" {
            $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            $descriptor.DiscretionaryAcl.Count | Should -Be 3
        }

        It "Should be able to parse complex but valid SDDL" {
            $sddl = "O:BAG:BAD:(A;;RPWPCCDCLCRCWOWDSDSW;;;SY)(A;;RPWPCCDCLCRCWOWDSDSW;;;BA)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;6da8a4ff-0e52-11d0-a286-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCRC;;;AU)S:(AU;SAFA;WDWOSDWPCCDCSW;;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            $descriptor.Owner | Should -Be "S-1-5-32-544"
            $descriptor.Group | Should -Be "S-1-5-32-544"
            $descriptor.DiscretionaryAcl.Count | Should -Be 7
            $descriptor.SystemAcl.Count | Should -Be 1
        }
    
        It "Should parse inheritance and propagation flags" {
            $sddl = "O:SYG:SYD:AI(A;OICI;0x1301bf;;;WD)(A;NPIO;0x1201bf;;;WD)"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            $descriptor.DiscretionaryAcl.Count | Should -Be 2
            $descriptor.DiscretionaryAcl[0].InheritanceFlags | Should -Be "ContainerInherit, ObjectInherit"
            $descriptor.DiscretionaryAcl[0].PropagationFlags | Should -Be "None"
            $descriptor.DiscretionaryAcl[1].InheritanceFlags | Should -Be "None"
            $descriptor.DiscretionaryAcl[1].PropagationFlags | Should -Be "NoPropagateInherit, InheritOnly"
        }
    
        It "Should be able to parse SDDL with D:NO_ACCESS_CONTROL" {
            $sddl = "O:SYG:SYD:NO_ACCESS_CONTROL"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            $descriptor.DiscretionaryAcl.Count | Should -Be 0
        }
    
        It "Should be able to parse SDDL without a DACL" {
            $descriptor = ConvertTo-SecurityDescriptor "O:SYG:SY"
            $descriptor.DiscretionaryAcl.Count | Should -Be 0
        }

        It "Should throw an error for SDDL containing domain-relative SID <Sid>" -ForEach @(
            @{ Sid = "CA" }, # CERT_PUBLISHERS, S-1-5-21-<domain>-517
            @{ Sid = "CN" }, # CLONEABLE_CONTROLLERS, S-1-5-21-<domain>-522
            @{ Sid = "DA" }, # DOMAIN_ADMINS, S-1-5-21-<domain>-512
            @{ Sid = "DC" }, # DOMAIN_COMPUTERS, S-1-5-21-<domain>-515
            @{ Sid = "DD" }, # DOMAIN_DOMAIN_CONTROLLERS, S-1-5-21-<domain>-516
            @{ Sid = "DG" }, # DOMAIN_GUESTS, S-1-5-21-<domain>-514
            @{ Sid = "DU" }, # DOMAIN_USERS, S-1-5-21-<domain>-513
            @{ Sid = "EA" }, # ENTERPRISE_ADMINS, S-1-5-21-<domain>-519
            @{ Sid = "PA" }, # GROUP_POLICY_CREATOR_OWNERS, S-1-5-21-<domain>-520
            @{ Sid = "RO" }, # ENTERPRISE_READONLY_DOMAIN_CONTROLLERS, S-1-5-21-<root domain>-498
            @{ Sid = "RS" }, # RAS_SERVERS, S-1-5-21-<domain>-553
            @{ Sid = "SA" } # SCHEMA_ADMINISTRATORS, S-1-5-21-<domain>-518
        ) {
            $sddl = "O:${Sid}G:BAD:NO_ACCESS_CONTROL"
            { ConvertTo-SecurityDescriptor $sddl } | Should -Throw
        }

        It "Should be able to parse SDDL with well-known machine-relative SID <Sid>" -ForEach @(
            # See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
            # See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
            @{ Sid = "LA"; SidMatches = "S-1-5-21-.*-500" }, # ADMINISTRATOR
            @{ Sid = "LG"; SidMatches = "S-1-5-21-.*-501" } # GUEST
        ) {
            $sddl = "O:${Sid}G:BAD:NO_ACCESS_CONTROL"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            $descriptor.Owner | Should -Match $SidMatches
        }

        It "Should be able to parse SDDL with well-known SID <Sid>" -ForEach @(
            # See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
            # See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
            @{ Sid = "AA"; SidValue = "S-1-5-32-579" }, # ACCESS_CONTROL_ASSISTANCE_OPS
            @{ Sid = "AC"; SidValue = "S-1-15-2-1" }, # ALL_APP_PACKAGES
            @{ Sid = "AN"; SidValue = "S-1-5-7" }, # ANONYMOUS
            @{ Sid = "AO"; SidValue = "S-1-5-32-548" }, # ACCOUNT_OPERATORS
            @{ Sid = "AU"; SidValue = "S-1-5-11" }, # AUTHENTICATED_USERS
            @{ Sid = "BA"; SidValue = "S-1-5-32-544" }, # BUILTIN_ADMINISTRATORS
            @{ Sid = "BG"; SidValue = "S-1-5-32-546" }, # BUILTIN_GUESTS
            @{ Sid = "BO"; SidValue = "S-1-5-32-551" }, # BACKUP_OPERATORS
            @{ Sid = "BU"; SidValue = "S-1-5-32-545" }, # BUILTIN_USERS
            @{ Sid = "CD"; SidValue = "S-1-5-32-574" }, # CERTSVC_DCOM_ACCESS, or CERTIFICATE_SERVICE_DCOM_ACCESS
            @{ Sid = "CG"; SidValue = "S-1-3-1" }, # CREATOR_GROUP
            @{ Sid = "CO"; SidValue = "S-1-3-0" }, # CREATOR_OWNER
            @{ Sid = "CY"; SidValue = "S-1-5-32-569" }, # CRYPTO_OPERATORS, or CRYPTOGRAPHIC_OPERATORS
            @{ Sid = "ED"; SidValue = "S-1-5-9" }, # ENTERPRISE_DOMAIN_CONTROLLERS
            @{ Sid = "ER"; SidValue = "S-1-5-32-573" }, # EVENT_LOG_READERS
            @{ Sid = "ES"; SidValue = "S-1-5-32-576" }, # RDS_ENDPOINT_SERVERS
            @{ Sid = "HA"; SidValue = "S-1-5-32-578" }, # HYPER_V_ADMINS
            @{ Sid = "HI"; SidValue = "S-1-16-12288" }, # ML_HIGH
            @{ Sid = "IS"; SidValue = "S-1-5-32-568" }, # IIS_USERS, or IIS_IUSRS
            @{ Sid = "IU"; SidValue = "S-1-5-4" }, # INTERACTIVE
            @{ Sid = "LS"; SidValue = "S-1-5-19" }, # LOCAL_SERVICE
            @{ Sid = "LU"; SidValue = "S-1-5-32-559" }, # PERFLOG_USERS
            @{ Sid = "LW"; SidValue = "S-1-16-4096" }, # ML_LOW
            @{ Sid = "ME"; SidValue = "S-1-16-8192" }, # ML_MEDIUM
            @{ Sid = "MP"; SidValue = "S-1-16-8448" }, # ML MEDIUM PLUS
            @{ Sid = "MS"; SidValue = "S-1-5-32-577" }, # RDS_MANAGEMENT_SERVERS
            @{ Sid = "MU"; SidValue = "S-1-5-32-558" }, # PERFMON_USERS
            @{ Sid = "NO"; SidValue = "S-1-5-32-556" }, # NETWORK_CONFIGURATION_OPS
            @{ Sid = "NS"; SidValue = "S-1-5-20" }, # NETWORK_SERVICE
            @{ Sid = "NU"; SidValue = "S-1-5-2" }, # NETWORK
            @{ Sid = "OW"; SidValue = "S-1-3-4" }, # OWNER_RIGHTS
            @{ Sid = "PO"; SidValue = "S-1-5-32-550" }, # PRINTER_OPERATORS
            @{ Sid = "PS"; SidValue = "S-1-5-10" }, # PRINCIPAL_SELF
            @{ Sid = "PU"; SidValue = "S-1-5-32-547" }, # POWER_USERS
            @{ Sid = "RA"; SidValue = "S-1-5-32-575" }, # RDS_REMOTE_ACCESS_SERVERS
            @{ Sid = "RC"; SidValue = "S-1-5-12" }, # RESTRICTED_CODE
            @{ Sid = "RD"; SidValue = "S-1-5-32-555" }, # REMOTE_DESKTOP
            @{ Sid = "RE"; SidValue = "S-1-5-32-552" }, # REPLICATOR
            @{ Sid = "RM"; SidValue = "S-1-5-32-580" }, # REMOTE_MANAGEMENT_USERS
            @{ Sid = "RU"; SidValue = "S-1-5-32-554" }, # ALIAS_PREW2KCOMPACC
            @{ Sid = "SI"; SidValue = "S-1-16-16384" }, # ML_SYSTEM
            @{ Sid = "SO"; SidValue = "S-1-5-32-549" }, # SERVER_OPERATORS
            @{ Sid = "SU"; SidValue = "S-1-5-6" }, # SERVICE
            @{ Sid = "SY"; SidValue = "S-1-5-18" }, # LOCAL_SYSTEM
            @{ Sid = "UD"; SidValue = "S-1-5-84-0-0-0-0-0" }, # USER_MODE_DRIVERS
            @{ Sid = "WD"; SidValue = "S-1-1-0" }, # EVERYONE
            @{ Sid = "WR"; SidValue = "S-1-5-33" } # WRITE_RESTRICTED_CODE
        ) {
            $sddl = "O:${Sid}G:BAD:NO_ACCESS_CONTROL"
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            [string]$descriptor.Owner | Should -Be $SidValue
        }

        It "Should be able to parse SDDL with access mask <AccessRight>" -ForEach @(
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
            @{ AccessRight = "FR"; Expected = 0x00120089 },
            # A few examples of literal access mask values
            @{ AccessRight = "0x1"; Expected = 0x1 },
            @{ AccessRight = "0x00000001"; Expected = 0x1 },
            @{ AccessRight = "0x2a"; Expected = 0x2A },
            @{ AccessRight = "0xAbCd"; Expected = 0xABCD },
            @{ AccessRight = "0x1F01FF"; Expected = 0x1F01FF },
            @{ AccessRight = "0x12345678"; Expected = 0x12345678 }
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
            $descriptor = ConvertTo-SecurityDescriptor $sddl
            
            $descriptor.DiscretionaryAcl.Count | Should -Be 1
            $mask = [int]$descriptor.DiscretionaryAcl[0].AccessMask
            $mask | Should -Be $Expected -Because "Expected access mask for $sddl to be $expected, but got $mask"
        }
        
        It "Should throw an error when the SDDL contains domain-relative SIDs" {
            { ConvertTo-SecurityDescriptor "O:DAB:SYD:NO_ACCESS_CONTROL" } | Should -Throw
        }

        It "Should throw an error when parsing invalid SDDL" {
            { ConvertTo-SecurityDescriptor "not valid SDDL :)" } | Should -Throw
        }
    }

    Describe "Binary" {
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

            $descriptor = ConvertTo-SecurityDescriptor $binary -InputFormat Binary
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

            $descriptor = ConvertTo-SecurityDescriptor $binary -InputFormat Binary
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

            ConvertTo-SecurityDescriptor $binary -InputFormat Binary `
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

            { ConvertTo-SecurityDescriptor $binary -From Binary } | Should -Throw 
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
            $descriptor = ConvertTo-SecurityDescriptor $base64 -InputFormat Base64
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
            { ConvertTo-SecurityDescriptor "not valid Base64 :)" -From Base64 } | Should -Throw
        }
    }
}

Describe "ConvertFrom-SecurityDescriptor" {
    It "Should return the same SDDL" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor $sddl
        $newSddl = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }

    It "Should be able to convert SDDL to base64 and back with pipelines" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $base64 = ConvertTo-SecurityDescriptor $sddl | ConvertFrom-SecurityDescriptor -OutputFormat Base64
        { [System.Convert]::FromBase64String($base64) } | Should -Not -Throw
        $newSddl = ConvertTo-SecurityDescriptor $base64 -InputFormat Base64 | ConvertFrom-SecurityDescriptor -OutputFormat Sddl
        $newSddl | Should -Be $sddl
    }

    It "Should be able to return binary" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor $sddl
        $binary = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Binary
        Should -ActualValue $binary -BeOfType [System.Object[]] # should be an array
        $binary | Should -BeOfType [byte] # each element should be a byte
    }

    It "Should be able to return valid base64" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor $sddl
        $base64 = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Base64
        $base64 | Should -BeOfType [string]
        { [System.Convert]::FromBase64String($base64) } | Should -Not -Throw
    }

    It "Should return equivalent base64 and binary" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $descriptor = ConvertTo-SecurityDescriptor $sddl
        $binary = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Binary
        $base64 = ConvertFrom-SecurityDescriptor $descriptor -OutputFormat Base64
        $binaryFromBase64 = [System.Convert]::FromBase64String($base64)
        $binary | Should -Be $binaryFromBase64
    }
}

Describe "Get-InferredAclFormat" {
    It "Should return Sddl for valid SDDL strings" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $format = Get-InferredAclFormat $sddl
        $format | Should -Be Sddl
    }

    It "Should return Base64 for valid Base64 strings" {
        $base64 = "AQAEhBQAAAAgAAAAAAAAACwAAAABAQAAAAAABRIAAAABAQAAAAAABRIAAAACAEQAAwAAAAAAFAC/ARMAAQEAAAAAAAEAAAAAABAUAL8BEgABAQAAAAAAAQAAAAAAABQA/wETAAEBAAAAAAAFCwAAAA=="
        $format = Get-InferredAclFormat $base64
        $format | Should -Be Base64
    }

    It "Should return Binary for valid binary arrays" {
        [byte[]]$binary = @(
            1, 0, 4, 132, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 44, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 2, 0, 68, 0, 3, 0, 0, 0, 0, 0, 20, 0, 191, 1, 19, 0, 1, 1, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 16, 20, 0, 191, 1, 18, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 20, 0, 255, 1, 19, 0, 1,
            1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0
        )
        $format = Get-InferredAclFormat $binary
        $format | Should -Be Binary
    }

    It "Should return Raw for valid RawSecurityDescriptor objects" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $rawSecurityDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        $format = Get-InferredAclFormat $rawSecurityDescriptor
        $format | Should -Be Raw
    }

    It "Should return FileAcl for valid CommonSecurityDescriptor objects with IsContainer false" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $rawSecurityDescriptor = [System.Security.AccessControl.CommonSecurityDescriptor]::new($false, $false, $sddl)
        $format = Get-InferredAclFormat $rawSecurityDescriptor
        $format | Should -Be FileAcl
    }

    It "Should return FolderAcl for valid CommonSecurityDescriptor objects with IsContainer true" {
        $sddl = "O:SYG:SYD:AI(A;;0x1301bf;;;WD)(A;ID;0x1201bf;;;WD)(A;;0x1301ff;;;AU)"
        $rawSecurityDescriptor = [System.Security.AccessControl.CommonSecurityDescriptor]::new($true, $false, $sddl)
        $format = Get-InferredAclFormat $rawSecurityDescriptor
        $format | Should -Be FolderAcl
    }
}