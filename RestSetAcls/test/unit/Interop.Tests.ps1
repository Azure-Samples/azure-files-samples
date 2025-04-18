BeforeAll {
    Import-Module $PSScriptRoot/../../RestSetAcls/Interop.psm1 -Force
}

Describe "Interop" {
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

                    $parentDescriptor = Convert-SecurityDescriptor $ParentSddl -From Sddl -To FolderAcl
                    $creatorDescriptor = Convert-SecurityDescriptor $ChildSddl -From Sddl -To FolderAcl
    
                    $result = CreatePrivateObjectSecurityEx -ParentDescriptor $parentDescriptor -CreatorDescriptor $creatorDescriptor -IsDirectory $true
    
                    $result | Should -Not -BeNullOrEmpty
                    $resultSddl = Convert-SecurityDescriptor $result -From FolderAcl -To Sddl
                    $reason = "inheritance with parent Sddl: $ParentSddl, creator sddl: $ChildSddl is not as expected"
                    $resultSddl | Should -Be $ExpectedSddl -Because $reason
                }
            }

            It "Only adds AI when there is nothing to inherit in the parent" {
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
              @{ ParentAceFlags = "CIIOID"; ChildAceFlags = "CIID" },
              # OICI
              @{ ParentAceFlags = "OICI"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIO"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIID"; ChildAceFlags = "OICIID" },
              @{ ParentAceFlags = "OICIIOID"; ChildAceFlags = "OICIID" }

            ) {
                Test-Inheritance `
                    -ParentSddl "O:BAG:BAD:(A;$($_.ParentAceFlags);FA;;;BA)" `
                    -ChildSddl "O:SYG:SYD:(A;;FA;;;SY)" `
                    -ExpectedSddl "O:SYG:SYD:AI(A;;FA;;;SY)(A;$($_.ChildAceFlags);FA;;;BA)"
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
        }
    }
}
