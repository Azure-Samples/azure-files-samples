function Init {
    Write-Host "Checking if PSDepend is installed" -ForegroundColor White
    $installed = $null -ne (Get-Module PSDepend -ListAvailable)

    if ($installed) {
        Write-Host "Already installed"
    }
    else {
        Write-Host "Not installed"
        Write-Host "`nInstalling PSDepend" -ForegroundColor White
        Install-Module -Name PSDepend -Repository PSGallery -Force
        Write-Host "Done"
    }

    Write-Host "`nInstalling build dependencies" -ForegroundColor White
    Invoke-PSDepend -Path $PSScriptRoot\build.depend.psd1 -Force
    Write-Host "Done"

    Write-Host "`nImporting build tools" -ForegroundColor White
    Import-Module $PSScriptRoot\build-tools.psm1 -Force
    Write-Host "Done"
}

Init