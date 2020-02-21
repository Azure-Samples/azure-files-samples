# Deploy DNS forwarder for Azure Files
- [Overview]
- [See also](#see-also)

## Overview
This ARM template is provided in order to simplify the deployment of DNS forwarders for use with Azure Files (and other Azure services). In order to create a highly available DNS forwarding solution, we will deploy two virtual machines within an availability set, which ensures that your DNS server VMs are isolated across multiple physical servers, compute racks, storage units, and network switches. When the deployment is complete, you will have deployed (where n is the number of instances that you select):

- n Windows Server 2019 virtual machines.
- n virtual disks (for the Windows Server OS).
- n virtual network interfaces.
- 1 availability set.

Through use of the CustomScriptExtension, the template will also:

- Install the DNS Server role.
- Auto-configure DNS forwarding rules as specified by the user.
- Domain join the server to a specified AD.

To learn more on how to use this template, see [Configuring DNS forwarding for Azure Files](https://docs.microsoft.com/azure/storage/files/storage-files-networking-dns).

## See also
- [Azure Files networking considerations](https://docs.microsoft.com/azure/storage/files/storage-files-networking-overview)
- [Azure Files networking endpoints](https://docs.microsoft.com/azure/storage/files/storage-files-networking-endpoints)
- [Name resolution for resources in Azure virtual networks](https://docs.microsoft.com/azure/virtual-network/virtual-networks-name-resolution-for-vms-and-role-instances)