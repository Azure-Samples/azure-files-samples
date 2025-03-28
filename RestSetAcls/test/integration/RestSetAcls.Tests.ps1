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
    Context "-File" {
        It "Should retrieve the permission key of a file" {
            $fileName = "$(New-RandomString -Length 8).txt"
            $fileInfo = New-File $fileName
            
            $file = Get-File $fileName
            $key = Get-AzFileAclKey -File $file
            
            Assert-IsAclKey $key
            $key | Should -Be $fileInfo.SmbProperties.FilePermissionKey
        }

        It "Should retrieve the permission key of a directory" {
            $dirName = "$(New-RandomString -Length 8).txt"
            $dirInfo = New-Directory $dirName
            
            $file = Get-File $dirName
            $key = Get-AzFileAclKey -File $file

            Assert-IsAclKey $key
            $key | Should -Be $dirInfo.SmbProperties.FilePermissionKey
        }
    }

    Context "-FileShareName -FilePath" {
        It "Should retrieve the permission key of a file" {
            $fileName = "$(New-RandomString -Length 8).txt"
            $fileInfo = New-File $fileName

            $key = Get-AzFileAclKey -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName

            Assert-IsAclKey $key
            $key | Should -Be $fileInfo.SmbProperties.FilePermissionKey
        }

        It "Should retrieve the permission key of a directory" {
            $dirName = "$(New-RandomString -Length 8).txt"
            $dirInfo = New-File $dirName

            $key = Get-AzFileAclKey -Context $global:context -FileShareName $global:fileShareName -FilePath $dirName

            Assert-IsAclKey $key
            $key | Should -Be $dirInfo.SmbProperties.FilePermissionKey
        }
    }
}

Describe "Get-AzFileAclFromKey" {
    Context "-Share" {
        It "Should retrieve the permission" {
            $fileName = "$(New-RandomString -Length 8).txt"
            $fileInfo = New-File $fileName
            
            $key = $fileInfo.SmbProperties.FilePermissionKey
            $permission = Get-AzFileAclFromKey -Key $key -Share $global:share
            
            $permission | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
        }
    }

    Context "-Context -FileShareName" {
        It "Should retrieve the permission" {
            $fileName = "$(New-RandomString -Length 8).txt"
            $fileInfo = New-File $fileName
            
            $key = $fileInfo.SmbProperties.FilePermissionKey
            $permission = Get-AzFileAclFromKey -Key $key -Context $global:context -FileShareName $global:fileShareName

            $permission | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
        }
    }
}

Describe "Get-AzFileAcl" {
    Context "-File" {
        It "Should retrieve the ACL of a file in SDDL format" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"

            $fileName = "$(New-RandomString -Length 8).txt"
            New-File $fileName
            $file = Get-File $fileName
            Set-AzFileAcl -File $file -Acl $sddl

            $file = Get-File $fileName
            $acl = Get-AzFileAcl -File $file -OutputFormat Sddl

            $acl | Should -Be $sddl
        }

        It "Should retrieve the ACL of a directory in SDDL format" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"

            $dirName = "$(New-RandomString -Length 8).txt"
            New-Directory $dirName
            $dir = Get-File $dirName
            Set-AzFileAcl -File $dir -Acl $sddl

            $dir = Get-File $dirName
            $acl = Get-AzFileAcl -File $dir -OutputFormat Sddl

            $acl | Should -Be $sddl
        }

        It "Should retrieve the ACL of a file in Base64 format" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"

            $fileName = "$(New-RandomString -Length 8).txt"
            New-File $fileName
            $file = Get-File $fileName
            Set-AzFileAcl -File $file -Acl $sddl

            $acl = Get-AzFileAcl -File $file -OutputFormat Base64

            Assert-IsBase64Acl $acl
        }
    }

    Context "-FileShareName -FilePath" {
        It "Should retrieve the ACL of a file in Base64 format" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
            $fileName = "$(New-RandomString -Length 8).txt"
            New-File $fileName
            $file = Get-File $fileName
            Set-AzFileAcl -File $file -Acl $sddl

            $acl = Get-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName -OutputFormat Base64
            
            Assert-IsBase64Acl $acl
            Convert-SecurityDescriptor $acl -From Base64 -To Sddl | Should -Be $sddl
        }

        It "Should retrieve the ACL of a directory in Base64 format" {
            $dirName = "$(New-RandomString -Length 8).txt"
            New-Directory $dirName

            $acl = Get-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -FilePath $dirName -OutputFormat Base64

            Assert-IsBase64Acl $acl
        }
    }

    Context "-File with Binary Output" {
        It "Should retrieve the ACL of a file in Binary format" {
            $fileName = "$(New-RandomString -Length 8).txt"
            New-File $fileName

            $file = Get-File $fileName
            $acl = Get-AzFileAcl -File $file -OutputFormat Binary

            Assert-IsBinaryAcl $acl
        }

        It "Should retrieve the ACL of a directory in Binary format" {
            $dirName = "$(New-RandomString -Length 8).txt"
            New-Directory $dirName

            $dir = Get-File $dirName
            $acl = Get-AzFileAcl -File $dir -OutputFormat Binary

            Assert-IsBinaryAcl $acl
        }
    }
}

Describe "New-AzFileAcl" {
    Context "-Context -FileShareName" {
        It "Should create a new permission key" {
            $sddl = "O:SYG:SYD:P(A;;FA;;;BA)"

            $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl
            Assert-IsAclKey $key

            $permission = Get-AzFileAclFromKey -Context $global:context -FileShareName $global:fileShareName -Key $key
            $permission | Should -Be "O:SYG:SYD:P(A;;FA;;;BA)S:NO_ACCESS_CONTROL"
        }
    }
}

Describe "Set-AzFileAclKey" {
    Context "-File" {
        It "Should set the permission key on a file" {
            $fileName = "$(New-RandomString -Length 8).txt"
            $fileInfo = New-File $fileName
            
            $keyBefore = $fileInfo.SmbProperties.FilePermissionKey
            $sddlBefore = Get-AzFileAclFromKey -Key $keyBefore -Share $global:share

            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)"
            $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl
            $file = Get-File $fileName
            $returnedKey = Set-AzFileAclKey -File $file -Key $key
            
            $file = Get-File $fileName
            $keyAfter = Get-AzFileAclKey -File $file
            $sddlAfter = Get-AzFileAclFromKey -Key $keyAfter -Share $global:share

            $sddlBefore | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
            $sddlAfter | Should -Be "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
            $returnedKey | Should -Be $key
            $keyAfter | Should -Be $key
            $keyAfter | Should -Not -Be $keyBefore
        }

        It "Should set the permission key on a directory" {
            $dirName = "$(New-RandomString -Length 8).txt"
            $dirInfo = New-Directory $dirName
            
            $keyBefore = $dirInfo.SmbProperties.FilePermissionKey
            $sddlBefore = Get-AzFileAclFromKey -Key $keyBefore -Share $global:share

            $sddl = "O:SYG:SYD:P(A;;FA;;;AU)"
            $key = New-AzFileAcl -Context $global:context -FileShareName $global:fileShareName -Acl $sddl
            $dir = Get-File $dirName
            $returnedKey = Set-AzFileAclKey -File $dir -Key $key
            
            $dir = Get-File $dirName
            $keyAfter = Get-AzFileAclKey -File $dir
            $sddlAfter = Get-AzFileAclFromKey -Key $keyAfter -Share $global:share

            $sddlBefore | Should -Be "O:SYG:SYD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICI;0x1301bf;;;AU)(A;;FA;;;SY)(A;OICIIO;GA;;;CO)"
            $sddlAfter | Should -Be "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
            $returnedKey | Should -Be $key
            $keyAfter | Should -Be $key
            $keyAfter | Should -Not -Be $keyBefore
        }
    }
}

Describe "Set-AzFileAcl" {
    BeforeDiscovery {
        function Get-LargeSddl {
            $sddl = "O:SYG:SYD:P"
            $i = 0
            while ($sddl.Length -lt 8500) {
                $sddl += "(A;;FA;;;S-1-5-21-1001-1001-1001-$i)"
                $i++
            }
            return $sddl
        }

        $largeSddl = Get-LargeSddl
        $smallSddl = "O:SYG:SYD:P(A;;FA;;;AU)"
    }

    Context "Sddl" {
        It "Should set a <size > permission on a <type>" -ForEach @(
            @{ Type = "file"; Size = "small"; Sddl = $smallSddl },
            @{ Type = "file"; Size = "large"; Sddl = $largeSddl },
            @{ Type = "directory"; Size = "small"; Sddl = $smallSddl },
            @{ Type = "directory"; Size = "large"; Sddl = $largeSddl }
        ) {
            param ($Type, $Size, $Sddl)

            $name = "$(New-RandomString -Length 8).txt"
            if ($Type -eq "file") {
                New-File $name
            } else {
                New-Directory $name
            }
            $file = Get-File $name

            $returnedKey = Set-AzFileAcl -File $file -Acl $Sddl        
            Assert-IsAclKey $returnedKey

            $sddlAfter = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share
            $sddlAfter | Should -Be "${Sddl}S:NO_ACCESS_CONTROL"
        }
    }

    Context "Base64" {
        It "Should set a <size > permission on a <type>" -ForEach @(
            @{ Type = "file"; Size = "small"; Sddl = $smallSddl },
            @{ Type = "file"; Size = "large"; Sddl = $largeSddl },
            @{ Type = "directory"; Size = "small"; Sddl = $smallSddl },
            @{ Type = "directory"; Size = "large"; Sddl = $largeSddl }
        ) {
            param ($Type, $Size, $Sddl)

            $name = "$(New-RandomString -Length 8).txt"
            if ($Type -eq "file") {
                New-File $name
            } else {
                New-Directory $name
            }
            $file = Get-File $name

            $base64 = Convert-SecurityDescriptor $sddl -From Sddl -To Base64
            $returnedKey = Set-AzFileAcl -File $file -Acl $base64 -AclFormat Base64
            Assert-IsAclKey $returnedKey
            
            $sddlAfter = Get-AzFileAclFromKey -Key $returnedKey -Share $global:share
            $sddlAfter | Should -Be "${Sddl}S:NO_ACCESS_CONTROL"
        }
    }
}
