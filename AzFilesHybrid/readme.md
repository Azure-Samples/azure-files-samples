# AzFilesHybrid
## Overview
The AzFilesHybrid PowerShell module provides cmdlets for deploying and configuring Azure Files. It offers cmdlets for domain joining storage accounts to your on-premises Active Directory, configuring your DNS servers, and troubleshooting  authentication issues. 
## Installation
### Prerequisites
[PowerShell 5.1+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-5.1) or [PowerShell 7+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#install-powershell-using-winget-recommended)) \
[.NET Framework 4.7.2+](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net472)
### Install From PSGallery (recommended)
Open a PowerShell7 terminal \
Paste in the following Code snippet and run \
`Install-Module -Name AzFilesHybrid` \
[For other installation options and the latest version](https://www.powershellgallery.com/packages/AzFilesHybrid/)
### Install From Zip File (legacy)
[Download latest release from our Releases Page](https://github.com/Azure-Samples/azure-files-samples/releases) \
Extract the zip folder in desired directory
## Uninstall
### If Installed From PSGallery
1. Open a PowerShell terminal 
2. Paste the following code snippet below and run \
`Uninstall-Module AzFilesHybrid`
### If Installed From Zip File
1. Find the directory where the zip file was extracted
2. Delete the extracted folder and its contents