param (
    [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$Context,
    [string]$FileShareName,
    [string]$BasePath,
    [int]$NumberDirs,
    [int]$NumberFilesPerDir,
    [int]$Depth
)

function New-Arborescence(
    $context,
    [string]$fileShareName,
    [string]$basePath,
    [int]$numberDirs,
    [int]$numberFilesPerDir,
    [int]$depth
) {
    if ($depth -eq 0)
    {
        # Create file
        for ($j = 1; $j -le $numberFilesPerDir; $j++)
        {
            $fileName = "file-$j.txt"
            $filePath = $dirPath + "/" + $fileName
            Write-Host "Creating file $filePath"

            # Create file locally
            $localFilePath = Join-Path -Path $env:TEMP -ChildPath $fileName
            New-Item -Path $localFilePath -Value "Hello world" -ItemType File -Force | Out-Null
            
            # Upload it
            Set-AzStorageFileContent `
                -Context $context `
                -ShareName $FileShareName `
                -Path $filePath `
                -Source $localFilePath `
                -Force

            # Remove local file
            Remove-Item -Path $localFilePath
        }
    }
    else
    {
        for ($i = 1; $i -le $numberDirs; $i++)
        {
            # Create dir
            $dirName = "dir-$i"
            $dirPath = $basePath + "/" + $dirName
            Write-Host "Creating dir $dirPath"
            
            New-AzStorageDirectory `
                    -Context $context `
                    -ShareName $FileShareName `
                    -Path $dirPath `
                    -ErrorAction SilentlyContinue | Out-Null

            # Recurse inside dir
            New-Arborescence `
                -context $context `
                -fileShareName $fileShareName `
                -basePath $dirPath `
                -numberDirs $numberDirs `
                -numberFilesPerDir $numberFilesPerDir `
                -depth ($depth - 1)
        }
    }
}

New-Arborescence `
    -context $context `
    -fileShareName $FileShareName `
    -numberDirs $NumberDirs `
    -numberFilesPerDir $NumberFilesPerDir `
    -depth $Depth