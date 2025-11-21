BeforeAll {
    # A bit of a hacky way to import the module being tested and its dependencies. Maybe InModuleScope
    # could be used instead in the future.
    Import-Module $PSScriptRoot/../../RestSetAcls/RestSetAcls.psd1 -Force
    Get-ChildItem -Path "$PSScriptRoot/../../RestSetAcls/Types/*.ps1" | ForEach-Object { . $_.FullName }
    . $PSScriptRoot/../../RestSetAcls/Helpers/Interop.ps1
}

Describe "Interop" {
    BeforeAll {
        function Test-CreatePrivateObjectSecurityEx {
            param (
                [Parameter(Mandatory = $true)]
                [string]$ParentSddl,

                [Parameter(Mandatory = $true)]
                [string]$ChildSddl,

                [Parameter(Mandatory = $true)]
                [string]$ExpectedSddl,

                [Parameter(Mandatory = $true)]
                [bool]$ChildIsDirectory
            )

            $childFormat = if ($ChildIsDirectory) { "FolderAcl" } else { "FileAcl" }

            $parentDescriptor = Convert-SecurityDescriptor $ParentSddl -From Sddl -To FolderAcl
            $creatorDescriptor = Convert-SecurityDescriptor $ChildSddl -From Sddl -To $childFormat
            
            $result = CreatePrivateObjectSecurityEx `
                -ParentDescriptor $parentDescriptor `
                -CreatorDescriptor $creatorDescriptor `
                -IsDirectory $ChildIsDirectory

            $result | Should -Not -BeNullOrEmpty
            $resultSddl = Convert-SecurityDescriptor $result -From $childFormat -To Sddl
            $reason = "inheritance with parent sddl: $ParentSddl, creator sddl: $ChildSddl is not as expected"
            $resultSddl | Should -Be $ExpectedSddl -Because $reason
        }
    }

    Describe "CreatePrivateObjectSecurityEx" {
        Context "Child is a folder" {
            BeforeAll {
                function Test-Inheritance {
                    param (
                        [Parameter(Mandatory = $true)]
                        [string]$ParentSddl,

                        [Parameter(Mandatory = $true)]
                        [string]$ChildSddl,

                        [Parameter(Mandatory = $true)]
                        [string]$ExpectedSddl
                    )

                    Test-CreatePrivateObjectSecurityEx `
                        -ParentSddl $ParentSddl `
                        -ChildSddl $ChildSddl `
                        -ExpectedSddl $ExpectedSddl `
                        -ChildIsDirectory $true
                }
            }

            It "Just adds AI when there is nothing to inherit in the parent" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Changes nothing when child is already AI and there is nothing to inherit in the parent" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:AI(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Inherits <ParentAceFlags> from parent as <ChildAceFlags>" -ForEach @(
              # OI
              @{ ParentAceFlags = "OI"; ChildAceFlags = "OIIOID" },
              @{ ParentAceFlags = "OIIO"; ChildAceFlags = "OIIOID" },
              @{ ParentAceFlags = "OIID"; ChildAceFlags = "OIIOID" },
              @{ ParentAceFlags = "OIIOID"; ChildAceFlags = "OIIOID" },
              # CI
              @{ ParentAceFlags = "CI"; ChildAceFlags = "CIID" },
              @{ ParentAceFlags = "CIIO"; ChildAceFlags = "CIID" },
              @{ ParentAceFlags = "CIID"; ChildAceFlags = "CIID" },
              @{ ParentAceFlags = "CINP"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "CIIOID"; ChildAceFlags = "CIID" },
              @{ ParentAceFlags = "CINPID"; ChildAceFlags = "ID" },
              # OICI
              @{ ParentAceFlags = "OICI"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIO"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIID"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIOID"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICINP"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OICINPID"; ChildAceFlags = "ID" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;$($_.ChildAceFlags);FA;;;BA)"
            }

            It "Does not inherit <ParentAceFlags> ACEs from parent" -ForEach @(
                @{ ParentAceFlags = "OINP" },
                @{ ParentAceFlags = "OINPID" },
                @{ ParentAceFlags = "OIIONP" },
                @{ ParentAceFlags = "OIIONPID" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Inherits nothing when parent ACL is '<ParentAclFlags>' and child ACL is '<ChildAclFlags>'" -ForEach @(
                @{ ParentAclFlags = ""; ChildAclFlags = "P" },
                @{ ParentAclFlags = ""; ChildAclFlags = "PAI" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "P" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "PAI" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "P" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "PAI" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:$($_.ParentAclFlags)(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:$($_.ChildAclFlags)(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:P(A;;FA;;;SY)"
            }

            It "Inherits parent ACE when parent ACL is '<ParentAclFlags>' and child ACL is '<ChildAclFlags>'" -ForEach @(
                @{ ParentAclFlags = "P"; ChildAclFlags = "" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "AI" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "AI" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:$($_.ParentAclFlags)(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:$($_.ChildAclFlags)(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;OICIID;FA;;;BA)"
            }

            It "Inherits nothing new if it already has the parent ACE" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;SY)" `
                    -ChildSddl "O:SYG:SYD:(A;OICIID;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;OICIID;FA;;;SY)"
            }

            It "Inherits parent ACEs if it has empty DACL" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;OICIID;FA;;;BA)"
            }

            It "Inherits parent ACEs if it has null DACL" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:NO_ACCESS_CONTROL" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;OICIID;FA;;;BA)"
            }
        }

        Context "Child is a file" {
            BeforeAll {
                function Test-Inheritance {
                    param (
                        [Parameter(Mandatory = $true)]
                        [string]$ParentSddl,

                        [Parameter(Mandatory = $true)]
                        [string]$ChildSddl,

                        [Parameter(Mandatory = $true)]
                        [string]$ExpectedSddl
                    )

                    Test-CreatePrivateObjectSecurityEx `
                        -ParentSddl $ParentSddl `
                        -ChildSddl $ChildSddl `
                        -ExpectedSddl $ExpectedSddl `
                        -ChildIsDirectory $false
                }
            }

            It "Just adds AI when there is nothing to inherit in the parent" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Changes nothing when child is already AI and there is nothing to inherit in the parent" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:AI(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Inherits <ParentAceFlags> from parent as <ChildAceFlags>" -ForEach @(
              # OI
              @{ ParentAceFlags = "OI"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OIIO"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OIID"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OIIOID"; ChildAceFlags = "ID" },
              # OICI
              @{ ParentAceFlags = "OICI"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OICIIO"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OICIID"; ChildAceFlags = "ID" },
              @{ ParentAceFlags = "OICIIOID"; ChildAceFlags = "ID" }

            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;$($_.ChildAceFlags);FA;;;BA)"
            }

            It "Does not inherit <ParentAceFlags> ACEs from parent" -ForEach @(
                # CI
                @{ ParentAceFlags = "CI" },
                @{ ParentAceFlags = "CIIO" },
                @{ ParentAceFlags = "CIID" },
                @{ ParentAceFlags = "CIIOID" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Inherits nothing when parent ACL is '<ParentAclFlags>' and child ACL is '<ChildAclFlags>'" -ForEach @(
                @{ ParentAclFlags = ""; ChildAclFlags = "P" },
                @{ ParentAclFlags = ""; ChildAclFlags = "PAI" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "P" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "PAI" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "P" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "PAI" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:$($_.ParentAclFlags)(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:$($_.ChildAclFlags)(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:P(A;;FA;;;SY)"
            }

            It "Inherits parent ACE when parent ACL is '<ParentAclFlags>' and child ACL is '<ChildAclFlags>'" -ForEach @(
                @{ ParentAclFlags = "P"; ChildAclFlags = "" },
                @{ ParentAclFlags = "P"; ChildAclFlags = "AI" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "" },
                @{ ParentAclFlags = "PAI"; ChildAclFlags = "AI" }
            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:$($_.ParentAclFlags)(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:$($_.ChildAclFlags)(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;ID;FA;;;BA)"
            }

            It "Inherits nothing new if it already has the parent ACE" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;SY)" `
                    -ChildSddl "O:SYG:SYD:(A;ID;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;ID;FA;;;SY)"
            }

            It "Inherits parent ACEs if it has empty DACL" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;ID;FA;;;BA)"
            }

            It "Inherits parent ACEs if it has null DACL" {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:NO_ACCESS_CONTROL" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;ID;FA;;;BA)"
            }
        }
    }

    Describe "Get-MappedAccessMask" -Tag "generic" {
        It "Maps GENERIC_READ to specific file rights" {
            $genericRead = [GenericRights]::GENERIC_READ
            $result = Get-MappedAccessMask -AccessMask $genericRead
            $result | Should -Be ([FileGenericRightsMapping]::FILE_GENERIC_READ)
        }

        It "Maps GENERIC_WRITE to specific file rights" {
            $genericWrite = [GenericRights]::GENERIC_WRITE
            $result = Get-MappedAccessMask -AccessMask $genericWrite
            $result | Should -Be ([FileGenericRightsMapping]::FILE_GENERIC_WRITE)
        }

        It "Maps GENERIC_EXECUTE to specific file rights" {
            $genericExecute = [GenericRights]::GENERIC_EXECUTE
            $result = Get-MappedAccessMask -AccessMask $genericExecute
            $result | Should -Be ([FileGenericRightsMapping]::FILE_GENERIC_EXECUTE)
        }

        It "Maps GENERIC_ALL to specific file rights" {
            $genericAll = [GenericRights]::GENERIC_ALL
            $result = Get-MappedAccessMask -AccessMask $genericAll
            $result | Should -Be ([FileGenericRightsMapping]::FILE_ALL_ACCESS)
        }

        It "Maps combination of generic rights correctly" {
            $genericReadWrite = [GenericRights]::GENERIC_READ -bor [GenericRights]::GENERIC_WRITE
            $result = Get-MappedAccessMask -AccessMask $genericReadWrite
            $expected = ([FileGenericRightsMapping]::FILE_GENERIC_READ -bor [FileGenericRightsMapping]::FILE_GENERIC_WRITE)
            $result | Should -Be $expected
        }

        It "Leaves non-generic rights unchanged" {
            $specificRight = [SpecificRights]::FILE_READ_DATA
            $result = Get-MappedAccessMask -AccessMask $specificRight
            $result | Should -Be $specificRight
        }

        It "Maps mixed generic and specific rights correctly" {
            $mixed = [GenericRights]::GENERIC_READ -bor [SpecificRights]::FILE_APPEND_DATA
            $result = Get-MappedAccessMask -AccessMask $mixed
            $expected = [FileGenericRightsMapping]::FILE_GENERIC_READ -bor [SpecificRights]::FILE_APPEND_DATA
            $result | Should -Be $expected
        }

        It "Handles zero access mask" {
            $result = Get-MappedAccessMask -AccessMask 0
            $result | Should -Be 0
        }
    }
}
