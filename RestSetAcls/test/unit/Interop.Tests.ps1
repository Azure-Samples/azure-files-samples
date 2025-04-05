BeforeAll {
    Import-Module $PSScriptRoot/../../RestSetAcls/Interop.psm1 -Force
}

Describe "Interop" {
    Describe "CreatePrivateObjectSecurityEx" {
        Context "Child is a folder" {
            BeforeAll {
                function Test {
                    param (
                        [Parameter(Mandatory = $true)]
                        [string]$ParentSddl,
                        [Parameter(Mandatory = $true)]
                        [string]$ChildSddl,
                        [Parameter(Mandatory = $true)]
                        [string]$ExpectedSddl
                    )

                    $parentDescriptor = Convert-SecurityDescriptor $ParentSddl -From Sddl -To FolderAcl
                    $creatorDescriptor = Convert-SecurityDescriptor $ChildSddl -From Sddl -To FolderAcl
    
                    $result = CreatePrivateObjectSecurityEx -ParentDescriptor $parentDescriptor -CreatorDescriptor $creatorDescriptor -IsDirectory $true
    
                    $result | Should -Not -BeNullOrEmpty
                    $resultSddl = Convert-SecurityDescriptor $result -From FolderAcl -To Sddl
                    $resultSddl | Should -Be $ExpectedSddl -Because "Parent Sddl: $ParentSddl, Child Sddl: $ChildSddl"
                }
            }

            It "Only adds AI when there is nothing to inherit in the parent" {
                Test `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Changes nothing when child is already AI and there is nothing to inherit in the parent" {
                Test `
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
              @{ ParentAceFlags = "CIIOID"; ChildAceFlags = "CIID" },
              # OICI
              @{ ParentAceFlags = "OICI"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIO"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIID"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIOID"; ChildAceFlags = "OICIID" }

            ) {
                Test `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;$($_.ChildAceFlags);FA;;;BA)"
            }

            It "Inherits nothing when child is marked as P" {
                Test `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:P(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:P(A;;FA;;;SY)"
            }
        }

        Context "Child is a file" {
            BeforeAll {
                function Test {
                    param (
                        [Parameter(Mandatory = $true)]
                        [string]$ParentSddl,
                        [Parameter(Mandatory = $true)]
                        [string]$ChildSddl,
                        [Parameter(Mandatory = $true)]
                        [string]$ExpectedSddl
                    )

                    $parentDescriptor = Convert-SecurityDescriptor $ParentSddl -From Sddl -To FolderAcl
                    $creatorDescriptor = Convert-SecurityDescriptor $ChildSddl -From Sddl -To FileAcl
    
                    $result = CreatePrivateObjectSecurityEx -ParentDescriptor $parentDescriptor -CreatorDescriptor $creatorDescriptor -IsDirectory $false
    
                    $result | Should -Not -BeNullOrEmpty
                    #$resultSddl = $result.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                    $resultSddl = Convert-SecurityDescriptor $result -From FileAcl -To Sddl
                    $resultSddl | Should -Be $ExpectedSddl -Because "Parent Sddl: $ParentSddl, Child Sddl: $ChildSddl"
                }
            }

            It "Only adds AI when there is nothing to inherit in the parent" {
                Test `
                    -ParentSddl "O:BAG:BAD:(A;;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Changes nothing when child is already AI and there is nothing to inherit in the parent" {
                Test `
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
                Test `
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
                Test `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)"
            }

            It "Inherits nothing when child is marked as P" {
                Test `
                    -ParentSddl "O:BAG:BAD:(A;OICI;FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:P(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:P(A;;FA;;;SY)"
            }
        }
    }
}
