
function Get-IsElevatedSession {
    <#
    .SYNOPSIS
    Get the elevation status of the PowerShell session.
    .DESCRIPTION
    This cmdlet will check to see if the PowerShell session is running as administrator, generally allowing PowerShell code 
    to check to see if it's got enough permissions to do the things it needs to do. This cmdlet is not yet defined on Linux/macOS
    sessions.
    
    .EXAMPLE
    if ((Get-IsElevatedSession)) {
        # Some code requiring elevation
    } else {
        # Some alternative code, or a nice error message.
    }
    .OUTPUTS 
    System.Boolean, indicating whether the session is elevated.
    #>

    [CmdletBinding()]
    param()

    switch((Get-OSPlatform)) {
        "Windows" {
            $currentPrincipal = [Security.Principal.WindowsPrincipal]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent())
            $isAdmin = $currentPrincipal.IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)

            return $isAdmin
        }

        "Linux" {
            throw [System.PlatformNotSupportedException]::new()
        }

        "OSX" {
            throw [System.PlatformNotSupportedException]::new()
        }

        default {
            throw [System.PlatformNotSupportedException]::new()
        }
    }
}
function Request-AzureADModule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="High")]
    param()

    if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0)) {
        $winCompat = Get-Module -Name WindowsCompatibility -ListAvailable
    }

    $azureADModule = Get-Module -Name AzureAD -ListAvailable
    if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0) -and $null -ne $winCompat) {
        $azureADModule = Invoke-WinCommand -Verbose:$false -ScriptBlock { 
            Get-Module -Name AzureAD -ListAvailable 
        }
    }

    if (
        ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0,0) -and $null -eq $winCompat) -or 
        $null -eq $azureADModule
    ) {
        $caption = "Install AzureAD PowerShell module"
        $verboseConfirmMessage = "This cmdlet requires the Azure AD PowerShell module. This can be automatically installed now if you are running in an elevated sessions."
        
        if ($PSCmdlet.ShouldProcess($verboseConfirmMessage, $verboseConfirmMessage, $caption)) {
            if (!(Get-IsElevatedSession)) {
                Write-Error `
                        -Message "To install AzureAD, you must run this cmdlet as an administrator. This cmdlet may not generally require administrator privileges." `
                        -ErrorAction Stop
            }

            if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0) -and $null -eq $winCompat) {
                Install-Module `
                        -Name WindowsCompatibility `
                        -Repository PSGallery `
                        -AllowClobber `
                        -Force `
                        -ErrorAction Stop

                Import-Module -Name WindowsCompatibility
            }
            
            $scriptBlock = { 
                $azureADModule = Get-Module -Name AzureAD -ListAvailable
                if ($null -eq $azureADModule) {
                    Install-Module `
                            -Name AzureAD `
                            -Repository PSGallery `
                            -AllowClobber `
                            -Force `
                            -ErrorAction Stop
                }
            }

            if ($PSVersionTable.PSVersion -gt [Version]::new(6,0,0)) {
                Invoke-WinCommand `
                        -ScriptBlock $scriptBlock `
                        -Verbose:$false `
                        -ErrorAction Stop
            } else {
                $scriptBlock.Invoke()
            }
        }
    }

    Remove-Module -Name PowerShellGet -ErrorAction SilentlyContinue
    Remove-Module -Name PackageManagement -ErrorAction SilentlyContinue
}

function Get-OSPlatform {
    <#
    .SYNOPSIS
    Get the OS running the current PowerShell session.
    .DESCRIPTION
    This cmdlet is a wrapper around the System.Runtime.InteropServices.RuntimeInformation .NET standard class that makes it easier to work with in PowerShell 5.1/6/7/etc. $IsWindows, etc. is defined in PS6+, however since it's not defined in PowerShell 5.1, it's not incredibly useful for writing PowerShell code meant to be executed in either language version. As older versions of .NET Framework do not support the RuntimeInformation .NET standard class, if the PSEdition is "Desktop", by default you're running on Windows, since only "Core" releases are cross-platform.
    .EXAMPLE
    if ((Get-OSPlatform) -eq "Windows") {
        # Do some Windows specific stuff
    }
    .OUTPUTS
    System.String, indicating the OS Platform name as defined by System.Runtime.InteropServices.RuntimeInformation.
    #>

    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        return "Windows"
    } else {
        $windows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows)

        if ($windows) { 
            return "Windows"
        }
        
        $linux = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Linux)

        if ($linux) {
            return "Linux"
        }

        $osx = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::OSX)

        if ($osx) {
            return "OSX"
        }

        return "Unknown"
    }
}

function Assert-IsWindows {
    <#
    .SYNOPSIS
    Check if the session is being run on Windows and throw an error if it isn't.
    .DESCRIPTION
    This cmdlet uses the Get-OSPlatform cmdlet to throw a nice error message to the user if the session isn't Windows.
    .EXAMPLE
    Assert-IsWindows
    # User either sees nothing or an error message.
    #>

    [CmdletBinding()]
    param()

    if ((Get-OSPlatform) -ne "Windows") {
        throw [PlatformNotSupportedException]::new()
    }
}

function Request-ConnectAzureAD {
    <#
    .SYNOPSIS
    Connect to an Azure AD tenant using the AzureAD cmdlets.
    .DESCRIPTION
    Correctly import the AzureAD module for your PowerShell version and then sign in using the same tenant is the currently signed in Az user. This wrapper is necessary as 1. AzureAD is not directly compatible with PowerShell 6 (though this can be achieved through the WindowsCompatibility module), and 2. AzureAD doesn't necessarily log you into the same tenant as the Az cmdlets according to their documentation (although it's not clear when it doesn't).
    .EXAMPLE
    Request-ConnectAzureAD
    #>

    [CmdletBinding()]
    param()

    Assert-IsWindows
    Request-AzureADModule

    $aadModule = Get-Module | Where-Object { $_.Name -like "AzureAD" }
    if ($null -eq $aadModule) {
        if ($PSVersionTable.PSVersion -ge [Version]::new(6,0,0,0)) {
            Import-WinModule -Name AzureAD -Verbose:$false
        } else {
            Import-Module -Name AzureAD
        }
    }

    try {
        Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
    } catch {
        $context = Get-AzContext
        Connect-AzureAD `
                -TenantId $context.Tenant.Id `
                -AccountId $context.Account.Id `
                -AzureEnvironmentName $context.Environment.Name | `
            Out-Null
    }
}


function Validate-StorageAccount {
    [CmdletBinding()]
    param (
         [Parameter(Mandatory=$true, Position=0)]
         [string]$ResourceGroupName,
         [Parameter(Mandatory=$true, Position=1)]
         [string]$StorageAccountName
    )

    process
    {
        $resourceGroupObject = Get-AzResourceGroup -Name $ResourceGroupName

        if ($null -eq $resourceGroupObject)
        {
            $message = "Resource group not found: '$ResourceGroupName'." `
                + " Please check whether the provided name '$ResourceGroupName' is valid or" `
                + " whether the resource group exists by running" `
                + " 'Get-AzResourceGroup -Name <ResourceGroupName>'" `
                + " (https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-powershell)"
            Write-Error -Message $message -ErrorAction Stop
        }

        $storageAccountObject = Get-AzStorageAccount -ResourceGroup $ResourceGroupName -Name $StorageAccountName

        if ($null -eq $storageAccountObject)
        {
            $message = "Storage account not found: '$StorageAccountName'." `
                + " Please check whether the provided name '$StorageAccountName' is valid or" `
                + " whether the storage account exists by running" `
                + " 'Get-AzStorageAccount -ResourceGroup <ResourceGroupName> -Name <StorageAccountName>'" `
                + " (https://docs.microsoft.com/en-us/powershell/module/az.storage/get-azstorageaccount?view=azps-4.4.0)"
            Write-Error -Message $message -ErrorAction Stop
        }

        Write-Verbose "Found storage Account '$StorageAccountName' in Resource Group '$ResourceGroupName'"

        return $storageAccountObject
    }
}


function Join-AzStorageAccountForAadKerberos {
 
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="StorageAccountName")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true, Position=1, ParameterSetName="StorageAccountName")]
        [Alias('Name')]
        [string]$StorageAccountName
    )

    begin {

    }

    process {

        if ($PSCmdlet.ParameterSetName -eq "StorageAccount") {
            $StorageAccountName = $StorageAccount.StorageAccountName;
            $ResourceGroupName = $StorageAccount.$ResourceGroupName;
        }

        <# Validate that the storage account exists. #>
        $storageaAccountObject = Validate-StorageAccount -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $StorageAccountName -ErrorAction Stop

        <# Use Az.Storage PowerShell to generate the kerb1 key of the storage account. #>

        <# Use Az.Storage PowerShell to retrieve the kerb1 key of the storage account and generate a password for the Azure AD Service Principal. #>
        $kerbKey1 = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey | Where-Object {$_.KeyName -like "kerb1"};
        $azureAdPasswordBuffer = [System.Linq.Enumerable]::Take([System.Convert]::FromBase64String($kerbKey1.Value), 32);
        $password = [System.Convert]::ToBase64String($azureAdPasswordBuffer);

        <# Connect to the Azure AD using your Azure AD cfedentials, retrieve tenant ID and domain name.#>
        
        try {
            $azureAdTenantDetail = Get-AzureADTenantDetail;
        }
        catch {
            $context = Get-AzContext
            Connect-AzureAD `
                    -TenantId $context.Tenant.Id `
                    -AccountId $context.Account.Id `
                    -AzureEnvironmentName $context.Environment.Name | `
                Out-Null

            $azureAdTenantDetail = Get-AzureADTenantDetail;    
        }

        $azureAdPrimaryDomain = ($azureAdTenantDetail.VerifiedDomains | Where-Object {$_._Default -eq $true}).Name;

        <# Generate the Service Principal Names for the Service Principal #>
        $servicePrincipalNames = New-Object string[] 3
        $servicePrincipalNames[0] = 'HTTP/{0}.file.core.windows.net' -f $StorageAccountName
        $servicePrincipalNames[1] = 'CIFS/{0}.file.core.windows.net' -f $StorageAccountName
        $servicePrincipalNames[2] = 'HOST/{0}.file.core.windows.net' -f $storageAccountName
    
        <# Create an application for the storage account. #>
        $application = New-AzureADApplication -DisplayName $storageAccountName  -IdentifierUris $servicePrincipalNames;

        <# Create a Service Principal for the storage account. #>
        $servicePrincipal = New-AzureADServicePrincipal -AccountEnabled $true -AppId $application.AppId -ServicePrincipalType "Application";

        <# Set the password of the Service Principal for the storage account. #>
        
        $Token = ([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens['AccessToken']).AccessToken

        $apiVersion = '1.6'
        $Uri = ('https://graph.windows.net/{0}/{1}/{2}?api-version={3}' -f $azureAdPrimaryDomain, 'servicePrincipals', $servicePrincipal.ObjectId, $apiVersion);

        $json = @"
{
    "passwordCredentials": [
    {
        "customKeyIdentifier": null,
        "endDate": "2022-07-30T19:12:51.3058279Z",
        "value": "<STORAGEACCOUNTPASSWORD>",
        "startDate": "2020-07-30T19:15:51.3058279Z"
    }]
}
"@

        $json -replace "<STORAGEACCOUNTPASSWORD>", $password

        $Headers = @{
                'authorization' = "Bearer $($Token)"
            }

        try {
            Invoke-RestMethod -Uri $Uri -ContentType 'application/json' -Method Patch -Headers $Headers -Body $json
            Write-Host "Success: Password is set for $storageAccountName"
        } catch {
            Write-Host $_.Exception.ToString()
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        }
}
}