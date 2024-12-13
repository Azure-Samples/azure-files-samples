function New-Arborescence {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Microsoft.WindowsAzure.Commands.Storage.AzureStorageContext]$context,
        [string]$FileShareName,
        [string]$BasePath,
        [int]$NumberDirs,
        [int]$NumberFilesPerDir,
        [int]$Depth
    )

    if ($Depth -eq 0) {
        # Create file
        for ($j = 1; $j -le $NumberFilesPerDir; $j++) {
            $fileName = "file-$j.txt"
            $filePath = $BasePath + "/" + $fileName
            $localFilePath = Join-Path -Path $env:TEMP -ChildPath $fileName

            if ($WhatIfPreference) {
                Write-Host "WhatIf: Creating file $filePath"
            }
            else {
                Write-Host "Creating file $filePath"

                # Create file locally
                New-Item `
                    -Path $localFilePath `
                    -Value "Hello world" `
                    -ItemType File `
                    -Force | Out-Null

                # Upload it
                Set-AzStorageFileContent `
                    -Context $Context `
                    -ShareName $FileShareName `
                    -Path $FilePath `
                    -Source $LocalFilePath `
                    -Force

                # Remove local file
                Remove-Item -Path $localFilePath
            }
        }
    }
    else {
        for ($i = 1; $i -le $NumberDirs; $i++) {
            # Create dir
            $dirPath = "${BasePath}/dir-$i"

            if ($WhatIfPreference) {
                Write-Host "WhatIf: Creating dir $dirPath"
            }
            else {
                Write-Host "Creating dir $dirPath"
                New-AzStorageDirectory `
                    -Context $Context `
                    -ShareName $FileShareName `
                    -Path $dirPath `
                    -ErrorAction SilentlyContinue | Out-Null
            }

            # Recurse inside dir
            New-Arborescence `
                -Context $Context `
                -FileShareName $FileShareName `
                -BasePath $dirPath `
                -NumberDirs $NumberDirs `
                -NumberFilesPerDir $NumberFilesPerDir `
                -Depth ($Depth - 1)
        }
    }
}

