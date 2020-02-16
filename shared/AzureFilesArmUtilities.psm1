function ConvertTo-EncodedJson {
    param(
        [string]$String,
        [int]$Depth = 2
    )

    $String = ($String | ConvertTo-Json -Compress -Depth $Depth).
        Replace("`"", "*").
        Replace("[", "<").
        Replace("]", ">").
        Replace("{", "^").
        Replace("}", "%")
    
    return $String
}

function ConvertFrom-EncodedJson {
    param(
        [string]$String
    )

    $String = $String.
        Replace("*", "`"").
        Replace("<", "[").
        Replace(">", "]").
        Replace("^", "{").
        Replace("%", "}")
    
    return (ConvertFrom-Json -InputObject $String)
}

function Write-OdjBlob {
    param(
        [string]$OdjBlob,
        [string]$Path
    )

    $byteArray = [System.Byte[]]@()
    $byteArray += 255
    $byteArray += 254

    $byteArray += [System.Text.Encoding]::Unicode.GetBytes($OdjBlob)

    $byteArray += 0
    $byteArray += 0

    $writer = [System.IO.File]::Create($Path)
    $writer.Write($byteArray, 0, $byteArray.Length)

    $writer.Close()
    $writer.Dispose()
}

function Join-WindowsMachine {
    param(
        [string]$OdjBlobPath,
        [string]$WindowsPath,
        [string]$JoinOutputPath
    )

    Invoke-Expression `
        -Command "djoin.exe /requestodj /loadfile `"$OdjBlobPath`" /windowspath $WindowsPath /localos" | `
    Out-File -FilePath $JoinOutputPath
}

function New-RegistryItem {
    param(
        [string]$ParentPath,
        [string]$Name
    )

    $regItem = Get-ChildItem -Path $ParentPath | `
        Where-Object { $_.PSChildName -eq $Name }
    
    if ($null -eq $regItem) {
        New-Item -Path ($ParentPath + "\" + $Name) | `
            Out-Null
    }
}

function New-RegistryItemProperty {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value
    )

    $regItemProperty = Get-ItemProperty -Path $Path | `
        Where-Object { $_.Name -eq $Name }
    
    if ($null -eq $regItemProperty) {
        New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value 1 | `
            Out-Null
    } else {
        Set-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value 1 | `
            Out-Null
    }
}