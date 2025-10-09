<#
.SYNOPSIS
    Quick demo: Enable SMB OAuth on Azure Storage Account via REST API

.DESCRIPTION
    This script demonstrates how to enable SMB OAuth using direct REST API calls.
    Compatible with PowerShell 5.1 and later.

.PARAMETER StorageAccountName
    The name of the Azure Storage Account

.PARAMETER ResourceGroup
    The resource group containing the storage account

.PARAMETER SubscriptionId
    The Azure subscription ID

.PARAMETER Location
    The Azure region location (default: northeurope)

.PARAMETER ApiVersion
    The Azure Management API version to use (default: 2025-01-01)

.PARAMETER EnableSmbOAuth
    Enable or disable SMB OAuth (default: $true)

.PARAMETER DisableSharedKeyAccess
    Disable shared key access (default: $true)

.EXAMPLE
    .\SMB_Oath.ps1 -StorageAccountName "mystorageacct" -ResourceGroup "myresourcegroup" -SubscriptionId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
    .\SMB_Oath.ps1 -StorageAccountName "mystorageacct" -ResourceGroup "myresourcegroup" -SubscriptionId "12345678-..." -DisableSharedKeyAccess $false

.NOTES
    Prerequisites: Connect-AzAccount must be run first
    Compatible with: PowerShell 5.1 and later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$false)]
    [string]$Location = "northeurope",

    [Parameter(Mandatory=$false)]
    [string]$ApiVersion = "2025-01-01",

    [Parameter(Mandatory=$false)]
    [bool]$EnableSmbOAuth = $true,

    [Parameter(Mandatory=$false)]
    [bool]$DisableSharedKeyAccess = $true
)

# ===================================================================
# GET ACCESS TOKEN
# ===================================================================
Write-Host "Getting Azure access token..." -ForegroundColor Cyan
$tokenResponse = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"

# Handle SecureString token (Az.Accounts 5.x+)
if ($tokenResponse.Token -is [System.Security.SecureString]) {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
} else {
    $token = $tokenResponse.Token
}

Write-Host "[OK] Token obtained" -ForegroundColor Green

# ===================================================================
# BUILD REST API URL
# ===================================================================
$apiUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccountName`?api-version=$ApiVersion"

Write-Host "REST API URL: $apiUrl" -ForegroundColor Gray

# ===================================================================
# CHECK CURRENT STATUS FIRST
# ===================================================================
Write-Host "`nChecking current configuration..." -ForegroundColor Cyan
$current = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}
# PowerShell 5.1 compatible conditional
if ($current.properties.azureFilesIdentityBasedAuthentication.smbOAuthSettings.isSmbOAuthEnabled) {
    $currentStatus = "Enabled"
} else {
    $currentStatus = "Disabled"
}
Write-Host "Current SMB OAuth Status: $currentStatus" -ForegroundColor Yellow

# ===================================================================
# ENABLE SMB OAUTH VIA REST API PATCH
# ===================================================================
if ($EnableSmbOAuth) {
    $actionText = "Enabling"
} else {
    $actionText = "Disabling"
}
Write-Host "`n$actionText SMB OAuth on $StorageAccountName..." -ForegroundColor Cyan

$body = @{
    location = $Location
    properties = @{
        azureFilesIdentityBasedAuthentication = @{
            directoryServiceOptions = "None"
            activeDirectoryProperties = $null
            smbOAuthSettings = @{
                isSmbOAuthEnabled = $EnableSmbOAuth
            }
        }
        allowSharedKeyAccess = -not $DisableSharedKeyAccess
    }
} | ConvertTo-Json -Depth 10

Write-Host "Sending PATCH request..." -ForegroundColor Gray
$response = Invoke-RestMethod -Uri $apiUrl -Method Patch -Headers @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
} -Body $body

Write-Host "[OK] PATCH request completed!" -ForegroundColor Green

# ===================================================================
# VERIFY CONFIGURATION
# ===================================================================
Write-Host "`nWaiting for Azure to apply changes..." -ForegroundColor Cyan
Start-Sleep -Seconds 5
Write-Host "Verifying configuration..." -ForegroundColor Cyan

$verify = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

# Extract values - PowerShell 5.1 compatible
if ($verify.properties.azureFilesIdentityBasedAuthentication.smbOAuthSettings.isSmbOAuthEnabled) {
    $smbOAuthEnabled = "Enabled"
} else {
    $smbOAuthEnabled = "Disabled"
}

if ($verify.properties.allowSharedKeyAccess) {
    $sharedKeyAccess = "Enabled"
} else {
    $sharedKeyAccess = "Disabled"
}

$directoryServiceOptions = $verify.properties.azureFilesIdentityBasedAuthentication.directoryServiceOptions
if (-not $directoryServiceOptions) {
    $directoryServiceOptions = "None"
}

# Get the file endpoint FQDN
$fileEndpoint = $verify.properties.primaryEndpoints.file
if ($fileEndpoint) {
    $fileEndpointFqdn = $fileEndpoint -replace "https://", "" -replace "/", ""
} else {
    $fileEndpointFqdn = "Not available"
}

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "      CONFIGURATION RESULT             " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Storage Account:        $StorageAccountName" -ForegroundColor Cyan
Write-Host "File Endpoint:          $fileEndpointFqdn" -ForegroundColor Cyan
Write-Host "SMB OAuth:              $smbOAuthEnabled" -ForegroundColor Green
Write-Host "Shared Key Access:      $sharedKeyAccess" -ForegroundColor Yellow
Write-Host "Directory Service:      $directoryServiceOptions" -ForegroundColor Magenta
Write-Host ""