# AzFilesHybrid
## Overview
The AzFilesHybrid PowerShell module provides cmdlets for deploying and configuring Azure Files. It offers cmdlets for domain joining storage accounts to your on-premises Active Directory, configuring your DNS servers, and troubleshooting  authentication issues. 

## Installation
### Prerequisites
- [PowerShell 5.1+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-5.1) or [PowerShell 7+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#install-powershell-using-winget-recommended)
- [.NET Framework 4.7.2+](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net472)
- A PowerShell Execution Policy of `RemoteSigned` or less restrictive (see [about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5)).

### Install From PSGallery (recommended, v0.3.3+)
First, check your current execution policy by running the following in a PowerShell window:

```powershell
Get-ExecutionPolicy -List
```

If the execution policy on `CurrentUser` is `Restricted` or `Undefined`, change it to `RemoteSigned` (or less restrictive, see [about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.5)). If the execution policy is `RemoteSigned`, `Default`, `AllSigned`, `Bypass` or `Unrestricted`, you can skip this step.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then, install AzFilesHybrid:

```powershell
Install-Module -Name AzFilesHybrid -Repository PSGallery
```

### Install From Zip File (legacy, v0.3.2 and older)
1. [Download latest release from our Releases Page](https://github.com/Azure-Samples/azure-files-samples/releases)
2. Extract the zip folder in desired directory
3. Open a PowerShell terminal, navigate to the directory of the extracted files
4. Run the following command
   ```powershell
   .\CopyToPath.ps1
   ```
## Uninstall
### If Installed From PSGallery
Run the following command in a PowerShell terminal:

```powershell
Uninstall-Module AzFilesHybrid
```

### If Installed From Zip File
1. Find the directory where the zip file was extracted by running the following in a PowerShell window:
   
   ```powershell
   Write-Host "$($env:PSModulePath.Split(";")[0])\AzFilesHybrid\"
   ```
   
2. Delete the folder(s) corresponding to the version(s) you want to uninstall.
