function Init {
    # Make sure PSGallery is registered
    Write-Host "Checking if PSGallery is registered" -ForegroundColor White
    $registered = $null -ne (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)
    if ($registered) {
        Write-Host "Already registered"
    }
    else {
        Write-Host "Not registered"
        Write-Host "`nRegistering PSGallery" -ForegroundColor White
        Register-PSRepository -Default
        Write-Host "Done"
    }

    # Make sure PSDepend is installed
    Write-Host "`nChecking if PSDepend is installed" -ForegroundColor White
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

    # Run PSDepend
    Write-Host "`nInstalling build dependencies" -ForegroundColor White
    Invoke-PSDepend -Path $PSScriptRoot\build.depend.psd1 -Force
    Write-Host "Done"

    # Import build tools to the current session
    Write-Host "`nImporting build tools" -ForegroundColor White
    Import-Module $PSScriptRoot\build-tools.psm1 -Force
    Write-Host "Done"
}

Init
