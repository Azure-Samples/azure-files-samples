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

    function New-RandomString {
        param (
            [int]$length = 8
        )
        $lowercase = 97..122        
        -join ($lowercase  | Get-Random -Count $length | ForEach-Object { [char]$_ })
    }

    # Build context from parameters
    $global:context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

    # Check that account exists
    $account = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
    if ($null -eq $account) {
        throw "Storage account $StorageAccountName not found in resource group $ResourceGroupName."
    }

    # Create a temporary file share in account
    $global:fileShareName = New-RandomString -length 12    
    Write-Host "Creating a temporary file share $global:fileShareName in storage account $StorageAccountName..."
    $global:share = New-AzStorageShare -Name $global:fileShareName -Context $global:context
    if ($null -eq $global:fileShareName) {
        throw "Failed to create a temporary file share in storage account $StorageAccountName."
    }

    $global:rootDirectoryClient = $global:share.ShareClient.GetRootDirectoryClient()

    function Get-File {
        [CmdletBinding()]
        [OutputType([Microsoft.WindowsAzure.Commands.Common.Storage.ResourceModel.AzureStorageFile])]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path
        )
        
        return Get-AzStorageFile -Context $global:context -ShareDirectoryClient $global:rootDirectoryClient -Path $Path
    }

    function New-File {
        [CmdletBinding()]
        [OutputType([Azure.Storage.Files.Shares.Models.ShareFileInfo])]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $false)]
            [int]$Size = 0
        )
        $file = $global:share.ShareClient.GetRootDirectoryClient().GetFileClient($Path)
        return $file.Create($Size).Value
    }

    function New-Directory {
        [CmdletBinding()]
        [OutputType([Azure.Storage.Files.Shares.Models.ShareDirectoryInfo])]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path
        )
        $directory = $global:share.ShareClient.GetRootDirectoryClient().GetSubdirectoryClient($Path)
        return $directory.Create().Value
    }
}

AfterAll {
    # Clean up the temporary file share
    if ($global:fileShareName) {
        Remove-AzStorageShare -Name $global:fileShareName -Context $global:context -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Temporary file share $global:fileShareName deleted."
    }
}

Describe "RestSetAcls" {
    Describe "Get-AzureFilePermissionKey" {
        Context "ParameterSet File" {
            It "Should retrieve the permission key" {
                $fileName = "$(New-RandomString -length 8).txt"
                $fileInfo = New-File $fileName
                
                $file = Get-File $fileName
                $key = Get-AzureFilePermissionKey -File $file

                $key | Should -Not -BeNullOrEmpty
                $key | Should -BeOfType [string]
                $key | Should -Match "^[0-9]+\*[0-9]+$"
                $key | Should -Be $fileInfo.SmbProperties.FilePermissionKey
            }
        }

        Context "ParameterSet FilePath" {
            It "Should retrieve the permission key" {
                $fileName = "$(New-RandomString -length 8).txt"
                $fileInfo = New-File $fileName

                $key = Get-AzureFilePermissionKey -Context $global:context -FileShareName $global:fileShareName -FilePath $fileName

                $key | Should -Not -BeNullOrEmpty
                $key | Should -BeOfType [string]
                $key | Should -Match "^[0-9]+\*[0-9]+$"
                $key | Should -Be $fileInfo.SmbProperties.FilePermissionKey
            }
        }
    }

    Describe "Get-AzureFilePermission" {
        Context "ParameterSet Share" {
            It "Should retrieve the permission" {
                $fileName = "$(New-RandomString -length 8).txt"
                $fileInfo = New-File $fileName
                
                $key = $fileInfo.SmbProperties.FilePermissionKey
                $permission = Get-AzureFilePermission -Key $key -Share $global:share
                
                $permission | Should -Not -BeNullOrEmpty
                $permission | Should -BeOfType [string]
                $permission | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
            }
        }

        Context "ParameterSet FileShareName" {
            It "Should retrieve the permission" {
                $fileName = "$(New-RandomString -length 8).txt"
                $fileInfo = New-File $fileName
                
                $key = $fileInfo.SmbProperties.FilePermissionKey
                $permission = Get-AzureFilePermission -Key $key -Context $global:context -FileShareName $global:fileShareName

                $permission | Should -Not -BeNullOrEmpty
                $permission | Should -BeOfType [string]
                $permission | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
            }
        }
    }

    Describe "New-AzureFilePermission" {
        Context "ParameterSet Sddl" {
            It "Should create a new permission key" {
                $sddl = "O:SYG:SYD:P(A;;FA;;;BA)"

                $key = New-AzureFilePermission -Context $global:context -FileShareName $global:fileShareName -Sddl $sddl
                $key | Should -Not -BeNullOrEmpty
                $key | Should -BeOfType [string]
                $key | Should -Match "^[0-9]+\*[0-9]+$"

                $permission = Get-AzureFilePermission -Context $global:context -FileShareName $global:fileShareName -Key $key
                $permission | Should -Be "O:SYG:SYD:P(A;;FA;;;BA)S:NO_ACCESS_CONTROL"
            }
        }
    }

    Describe "Set-AzureFilePermissionKey" {
        Context "ParameterSet File" {
            It "Should set the permission key" {
                $fileName = "$(New-RandomString -length 8).txt"
                $fileInfo = New-File $fileName
                
                $keyBefore = $fileInfo.SmbProperties.FilePermissionKey
                $sddlBefore = Get-AzureFilePermission -Key $keyBefore -Share $global:share

                $sddl = "O:SYG:SYD:P(A;;FA;;;AU)"
                $key = New-AzureFilePermission -Context $global:context -FileShareName $global:fileShareName -Sddl $sddl
                $file = Get-File $fileName
                $returnedKey = Set-AzureFilePermissionKey -File $file -Key $key
                
                $file = Get-File $fileName
                $keyAfter = Get-AzureFilePermissionKey -File $file
                $sddlAfter = Get-AzureFilePermission -Key $keyAfter -Share $global:share

                $sddlBefore | Should -Be "O:SYG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1301bf;;;AU)(A;;FA;;;SY)"
                $sddlAfter | Should -Be "O:SYG:SYD:P(A;;FA;;;AU)S:NO_ACCESS_CONTROL"
                $returnedKey | Should -Be $key
                $keyAfter | Should -Be $key
                $keyAfter | Should -Not -Be $keyBefore
            }
        }
    }
}