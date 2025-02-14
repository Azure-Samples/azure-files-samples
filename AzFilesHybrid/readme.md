# AzFilesHybrid
## Overview
The AzFilesHybrid PowerShell module provides cmdlets for deploying and configuring Azure Files. It offers cmdlets for domain joining storage accounts to your on-premises Active Directory, configuring your DNS servers, and troubleshooting  authentication issues. 
## Installation
### Prerequisites
- [PowerShell 5.1+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-5.1) or [PowerShell 7+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#install-powershell-using-winget-recommended)
- [.NET Framework 4.7.2+](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net472)
### Install From PSGallery (recommended)
Run the following in a PowerShell window
```powershell
Install-Module -Name AzFilesHybrid
```
### Install From Zip File (legacy)
1. [Download latest release from our Releases Page](https://github.com/Azure-Samples/azure-files-samples/releases) \
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
1. Find the directory where the zip file was extracted
2. Delete the extracted folder and its contents