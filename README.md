## Azure Files
Azure Files provides serverless cloud file shares that can be used from anywhere in the world. You can mount Azure file shares directly from your on-premises workstation, or you can cache Azure file shares on an on-premises file server with Azure File Sync. To learn more about Azure Files, please see [Introduction to Azure Files](https://docs.microsoft.com/azure/storage/files/storage-files-introduction), [Planning for an Azure Files deployment](https://docs.microsoft.com/azure/storage/files/storage-files-planning), and [Planning for an Azure File Sync deployment](https://docs.microsoft.com/azure/storage/files/storage-sync-files-planning). You can also reach out to us directly by sending us an email at <a href="mailto:AzureFiles@microsoft.com">AzureFiles@microsoft.com</a>.

### About this repository
This repository contains supporting code (PowerShell modules/scripts, ARM templates, etc.) for deploying, configuring, and using Azure Files. This repository is home to the following important projects:

- The [AzFilesHybrid PowerShell module](./AzFilesHybrid/readme.md), which provides cmdlets for deploying and configuring Azure Files, namely, cmdlets for domain joining storage accounts to your on-premises Active Directory, and configuring your DNS servers.

- An Azure template for deploying [DNS forwarders](./dns-forwarder/readme.md), which provides an ARM template for deploying DNS forwarders. This template is used by the AzFilesHybrid module.

- Instructions for setting up a Point-to-Site VPN (P2S) to bypass port 445. The most up-to-date instructions for configuring a Point-to-Site VPN are available [here](https://docs.microsoft.com/azure/storage/files/storage-files-configure-p2s-vpn-windows), however, we have maintained this information in this repository for now since the P2S here use a slightly different approach some customers may find useful.

### How to contribute
We welcome issue submission and direct contributions. Please feel free to create pull requests or issues as needed.

### Additional Resources
- [Azure-Samples/azure-files-samples repository](https://github.com/Azure-Samples/azure-files-samples): This repository contains various samples and scripts for working with Azure Files, including examples for using the Azure Files REST API, PowerShell scripts, and ARM templates.
