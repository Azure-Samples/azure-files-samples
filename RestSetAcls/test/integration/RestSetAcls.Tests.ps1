param (
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountKey
)

BeforeAll {
    Import-Module $PSScriptRoot/../../RestSetAcls/RestSetAcls.psd1 -Force
    Import-Module $PSScriptRoot/utils.psm1 -Force

    # Build context from parameters
    $global:context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

    # Check that account exists
    $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
    if ($null -eq $account) {
        throw "Storage account $StorageAccountName not found in resource group $ResourceGroupName."
    }

    # Create a temporary file share in account
    $global:fileShareName = New-RandomString -Length 12    
    Write-Host "Creating a temporary file share $global:fileShareName in storage account $StorageAccountName..."
    $global:share = New-AzStorageShare -Name $global:fileShareName -Context $global:context
    if ($null -eq $global:fileShareName) {
        throw "Failed to create a temporary file share in storage account $StorageAccountName."
    }

    $global:rootDirectoryClient = $global:share.ShareClient.GetRootDirectoryClient()
}

AfterAll {
    # Clean up the temporary file share
    if ($global:fileShareName) {
        Remove-AzStorageShare -Name $global:fileShareName -Context $global:context -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Temporary file share $global:fileShareName deleted."
    }
}

Describe "Get-AzFileAclKey" {
    Context "<type>" -ForEach @(
        @{ Type = "file" },
        @{ Type = "directory" }
    ) {
        BeforeEach {
            # Create file or directory
            if ($_.Type -eq "file") {
                $fileName = "$(New-RandomString -Length 8).txt"
                $fileInfo = New-File -Path $fileName -Size 1024
                $expectedKey = $fileInfo.SmbProperties.FilePermissionKey
            } elseif ($_.Type -eq "directory") {
                $fileName = New-RandomString -Length 8
                $dirInfo = New-Directory $fileName
                $expectedKey = $dirInfo.SmbProperties.FilePermissionKey
            } else {
                throw "Invalid type specified. Use 'file' or 'directory'."
            }

            # Get a reference to it
            $file = Get-File $fileName
        }

        Describe "-File" {
            It "Should retrieve the permission key" {
                $key = Get-AzFileAclKey -File $file

                Assert-IsAclKey $key
                $key | Should -Be $expectedKey
            }
        }

        Describe "-Context -FileShareName -FilePath" {
            It "Should retrieve the permission key" {
                $key = Get-AzFileAclKey -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName

                Assert-IsAclKey $key
                $key | Should -Be $expectedKey
            }
        }
    }
}

Describe "Get-AzFileAclFromKey" {
    Context "<type>" -ForEach @(
        @{ Type = "file" },
        @{ Type = "directory" }
    ) {
        BeforeEach {
            # Create file or directory, and get the key
            if ($_.Type -eq "file") {
                $fileName = "$(New-RandomString -Length 8).txt"
                $fileInfo = New-File -Path $fileName -Size 1024
                $key = $fileInfo.SmbProperties.FilePermissionKey
                $defaultSddl = "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
            }
            elseif ($_.Type -eq "directory") {
                $fileName = New-RandomString -Length 8
                $dirInfo = New-Directory $fileName
                $key = $dirInfo.SmbProperties.FilePermissionKey
                $defaultSddl = "O:SYG:SYD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICI;0x1301bf;;;AU)(A;;FA;;;SY)(A;OICIIO;GA;;;CO)"
            }
            else {
                throw "Invalid type specified. Use 'file' or 'directory'."
            }
        }

        Describe "-Share" {
            It "Should retrieve the default permission" {
                $permission = Get-AzFileAclFromKey -Key $key -Share $global:share

                $permission | Should -Be $defaultSddl
            }
        }

        Describe "-Context -FileShareName" {
            It "Should retrieve the default permission" {
                $permission = Get-AzFileAclFromKey -Key $key -Context $global:context -FileShareName $global:fileShareName

                $permission | Should -Be $defaultSddl
            }
        }

        Describe "-ShareClient" {
            It "Should retrieve the default permission" {
                $permission = Get-AzFileAclFromKey -Key $key -ShareClient $global:share.ShareClient

                $permission | Should -Be $defaultSddl
            }
        }
    }
}

Describe "Get-AzFileAcl" {
    Context "<type>" -ForEach @(
        @{ Type = "file"; Sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL" },
        @{ Type = "directory"; Sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL" }
    ) {
        BeforeEach {
            # Create file or directory
            if ($_.Type -eq "file") {
                $fileName = "$(New-RandomString -Length 8).txt"
                New-File -Path $fileName -Size 1024
            } elseif ($_.Type -eq "directory") {
                $fileName = New-RandomString -Length 8
                New-Directory $fileName
            } else {
                throw "Invalid type specified. Use 'file' or 'directory'."
            }

            # Set the ACL
            $file = Get-File $fileName
            Set-AzFileAcl -File $file -Acl $_.Sddl

            # Get a reference to it
            $file = Get-File $fileName
        }

        Describe "-File" {
            It "Should retrieve the ACL in SDDL format" {
                $acl = Get-AzFileAcl -File $file -OutputFormat Sddl
                $acl | Should -Be $_.Sddl
            }

            It "Should retrieve the ACL in Base64 format" {
                $acl = Get-AzFileAcl -File $file -OutputFormat Base64
                Assert-IsBase64Acl $acl
                Convert-SecurityDescriptor $acl -From Base64 -To Sddl | Should -Be $_.Sddl
            }
        }

        Describe "-FileShareName -FilePath" {
            It "Should retrieve the ACL in SDDL format" {
                $acl = Get-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName -OutputFormat Sddl
                $acl | Should -Be $_.Sddl
            }

            It "Should retrieve the ACL in Base64 format" {
                $acl = Get-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName -OutputFormat Base64
                Assert-IsBase64Acl $acl
                Convert-SecurityDescriptor $acl -From Base64 -To Sddl | Should -Be $_.Sddl
            }
        }
    }
}

Describe "New-AzFileAcl" {
    Describe "-Context -FileShareName" {
        It "Should create a new permission key" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;BA)"

            $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl
            Assert-IsAclKey $key

            $permission = Get-AzFileAclFromKey -Context $global:context -FileShareName $global:fileShareName -Key $key
            $permission | Should -Be "O:SYG:SYD:P(A;;FA;;;BA)S:NO_ACCESS_CONTROL"
        }
    }

    Describe "-ShareClient" {
        It "Should create a new permission key" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;BA)"

            $key = New-AzFileAcl -ShareClient $global:share.ShareClient -Acl $sddl
            Assert-IsAclKey $key

            $permission = Get-AzFileAclFromKey -Context $global:context -FileShareName $global:fileShareName -Key $key
            $permission | Should -Be "O:SYG:SYD:P(A;;FA;;;BA)S:NO_ACCESS_CONTROL"
        }
    }
}

Describe "Set-AzFileAclKey" {
    Context "<type>" -ForEach @(
        @{ Type = "file" },
        @{ Type = "directory" }
    ) {
        BeforeEach {
            # Create file or directory
            if ($_.Type -eq "file") {
                $fileName = "$(New-RandomString -Length 8).txt"
                $fileInfo = New-File -Path $fileName -Size 1024
                $keyBefore = $fileInfo.SmbProperties.FilePermissionKey
            } elseif ($_.Type -eq "directory") {
                $fileName = New-RandomString -Length 8
                $dirInfo = New-Directory $fileName
                $keyBefore = $dirInfo.SmbProperties.FilePermissionKey
            } else {
                throw "Invalid type specified. Use 'file' or 'directory'."
            }

            # Get a reference to it
            $file = Get-File $fileName
            $client = if ($_.Type -eq "file") { $file.ShareFileClient } else { $file.ShareDirectoryClient }
        }

        Describe "-File" {
            It "Should set the permission key" {
                $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
                $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl

                $keyAfter = Set-AzFileAclKey -File $file -Key $key
                
                Assert-IsAclKey $keyAfter
                $keyAfter | Should -Not -Be $keyBefore
                $sddlAfter = Get-AzFileAclFromKey -Key $keyAfter -Share $global:share
                $sddlAfter | Should -Be $sddl
            }
        }

        Describe "-Context -FileShareName -FilePath" {
            It "Should set the permission key" {
                $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
                $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl

                $keyAfter = Set-AzFileAclKey -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName -Key $key
                
                Assert-IsAclKey $keyAfter
                $keyAfter | Should -Not -Be $keyBefore
                $sddlAfter = Get-AzFileAclFromKey -Key $keyAfter -Context $global:context -FileShareName $global:fileShareName
                $sddlAfter | Should -Be $sddl
            }
        }

        Describe "-Client" {
            It "Should set the permission key" {
                $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
                $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl

                $keyAfter = Set-AzFileAclKey -Client $client -Key $key
                
                Assert-IsAclKey $keyAfter
                $keyAfter | Should -Not -Be $keyBefore
                $sddlAfter = Get-AzFileAclFromKey -Key $keyAfter -Context $global:context -FileShareName $global:fileShareName
                $sddlAfter | Should -Be $sddl
            }
        }
    }
}

Describe "Set-AzFileAcl" {
    Context "<type>" -ForEach @(
        @{ Type = "file" },
        @{ Type = "directory" }
    ) {
        BeforeDiscovery {
            $smallSddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
            $smallBase64 = Convert-SecurityDescriptor $smallSddl -From Sddl -To Base64

            function Get-LargeSddl {
                $sddl = "O:SYG:SYD:P"
                $i = 0
                while ($sddl.Length -lt 8500) {
                    $sddl += "(A;;FA;;;S-1-5-21-1001-1001-1001-$i)"
                    $i++
                }
                return "${sddl}S:NO_ACCESS_CONTROL"
            }
    
            $largeSddl = Get-LargeSddl
            $largeBase64 = Convert-SecurityDescriptor $largeSddl -From Sddl -To Base64
        }

        BeforeEach {
            # Create file or directory
            if ($Type -eq "file") {
                $fileName = "$(New-RandomString -Length 8).txt"
                New-File -Path $fileName -Size 1024
            } elseif ($Type -eq "directory") {
                $fileName = New-RandomString -Length 8
                New-Directory $fileName
            } else {
                throw "Invalid type specified. Use 'file' or 'directory'."
            }

            # Get a reference to it
            $file = Get-File $fileName
            $client = if ($Type -eq "file") { $file.ShareFileClient } else { $file.ShareDirectoryClient }
        }

        Describe "-File" {
            It "Should set a <size> SDDL permission" -ForEach @(
                @{ Size = "small"; Sddl = $smallSddl },
                @{ Size = "large"; Sddl = $largeSddl }
            ) {
                $returnedKey = Set-AzFileAcl -File $file -Acl $Sddl        
                Assert-IsAclKey $returnedKey

                $sddlAfter = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share
                $sddlAfter | Should -Be $Sddl
            }

            It "Should set a <size> base64 permission" -ForEach @(
                @{ Size = "small"; Base64 = $smallBase64 },
                @{ Size = "large"; Base64 = $largeBase64 }
            ) {
                $returnedKey = Set-AzFileAcl -File $file -Acl $Base64 -AclFormat Base64
                Assert-IsAclKey $returnedKey
                
                $base64After = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share -OutputFormat Base64
                $base64After | Should -Be $Base64
            }
        }

        Describe "-Client" {
            It "Should set a <size> SDDL permission" -ForEach @(
                @{ Size = "small"; Sddl = $smallSddl },
                @{ Size = "large"; Sddl = $largeSddl }
            ) {
                $returnedKey = Set-AzFileAcl -Client $client -Acl $Sddl
                Assert-IsAclKey $returnedKey

                $sddlAfter = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share
                $sddlAfter | Should -Be $Sddl
            }

            It "Should set a <size> base64 permission" -ForEach @(
                @{ Size = "small"; Base64 = $smallBase64 },
                @{ Size = "large"; Base64 = $largeBase64 }
            ) {
                $returnedKey = Set-AzFileAcl -Client $client -Acl $Base64 -AclFormat Base64
                Assert-IsAclKey $returnedKey
                
                $base64After = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share -OutputFormat Base64
                $base64After | Should -Be $Base64
            }
        }
    }
}
