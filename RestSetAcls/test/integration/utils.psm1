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

function New-RandomString {
    param (
        [int]$Length = 8
    )
    $lowercase = 97..122        
    -join ($lowercase  | Get-Random -Count $length | ForEach-Object { [char]$_ })
}

function Assert-IsBinaryAcl {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [object]$Acl
    )

    $Acl | Should -Not -BeNullOrEmpty
    Should -ActualValue $Acl -BeOfType [object[]]
    $Acl | Should -BeOfType [byte]
    { Convert-SecurityDescriptor $Acl -From Binary -To Raw } | Should -Not -Throw
}

function Assert-IsBase64Acl {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [object]$Acl
    )

    $Acl | Should -Not -BeNullOrEmpty
    $Acl | Should -BeOfType [string]
    $Acl | Should -Match "^[A-Za-z0-9+/=]+$"
    { [Convert]::FromBase64String($Acl) } | Should -Not -Throw
    { Convert-SecurityDescriptor $Acl -From Base64 -To Raw } | Should -Not -Throw
}

function Assert-IsAclKey {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [object]$Key
    )

    $Key | Should -Not -BeNullOrEmpty
    $Key | Should -BeOfType [string]
    $Key | Should -Match "^[0-9]+\*[0-9]+$"
}
