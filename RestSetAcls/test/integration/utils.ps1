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