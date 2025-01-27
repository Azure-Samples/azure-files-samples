#
# Module manifest for module 'HybridManagement'
#
# Generated by: Microsoft
#
# Generated on: 1/20/2020
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'AzFilesHybrid.psm1'
    
    # Version number of this module.
    ModuleVersion = '0.3.3.0'
    
    # Supported PSEditions
    CompatiblePSEditions = "Core", "Desktop"
    
    # ID used to uniquely identify this module
    GUID = '71b01ebd-3815-409f-9c24-6f10ef575705'
    
    # Author of this module
    Author = 'Microsoft Corporation'
    
    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'
    
    # Copyright statement for this module
    Copyright = '(c) 2020 Microsoft'
    
    # Description of the functionality provided by this module
    Description = 'The AzFilesHybrid PowerShell module provides cmdlets for deploying and configuring Azure Files. It offers cmdlets for domain joining storage accounts to your on-premises Active Directory, configuring your DNS servers, and troubleshooting  authentication issues.'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''
    
    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = '5.1'
    
    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''
    
    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''
    
    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(
        @{
            ModuleName = "Az.Accounts"
            GUID = "17a2feff-488b-47f9-8729-e2cec094624c"
            ModuleVersion = "4.0.1"
        },
        @{
            ModuleName = "Az.Compute"
            GUID = "d4cb9989-9ed1-49c2-bacd-0f8daf758671"
            ModuleVersion = "9.0.1"
        },
        @{
            ModuleName = "Az.Network"
            GUID = "f554cfcd-9cbb-4021-b158-fe20f0497f82"
            ModuleVersion = "7.12.0"
        },
        @{
            ModuleName = "Az.Resources"
            GUID = "48bb344d-4c24-441e-8ea0-589947784700"
            ModuleVersion = "7.8.0"
        },
        @{
            ModuleName = "Az.Storage"
            GUID = "dfa9e4ea-1407-446d-9111-79122977ab20"
            ModuleVersion = "8.1.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Applications"
            GUID = "467f54f2-44a8-4993-8e75-b96c3e443098"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Authentication"
            GUID = "883916f2-9184-46ee-b1f8-b6a2fb784cee"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Groups"
            GUID = "50bc9e18-e281-4208-8913-c9e1bef6083d"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Identity.DirectoryManagement"
            GUID = "c767240d-585c-42cb-bb2f-6e76e6d639d4"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Identity.SignIns"
            GUID = "60f889fa-f873-43ad-b7d3-b7fc1273a44f"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "Microsoft.Graph.Users"
            GUID = "71150504-37a3-48c6-82c7-7a00a12168db"
            ModuleVersion = "2.2.0"
        },
        @{
            ModuleName = "PSStyle"
            GUID = "aebeb4be-3ed1-4712-aaf6-b47c896dd97c"
            ModuleVersion = "1.1.8"
        }
    )
    
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    #NestedModules = 'HybridManagement.psm1'
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = "Get-IsElevatedSession",
        "Assert-IsElevatedSession",
        "Get-OSPlatform",
        "Assert-IsWindows",
        "Get-IsDomainJoined",
        "Assert-IsDomainJoined",
        "Get-OSVersion",
        "Get-WindowsInstallationType",
        "Get-OSFeature",
        "Install-OSFeature",
        "Request-OSFeature",
        "Get-RandomString",
        "Assert-DotNetFrameworkVersion",
        "Register-OfflineMachine",
        "Join-OfflineMachine",
        "ConvertFrom-EncodedJson",
        "ConvertTo-EncodedJson",
        "New-RegistryItem",
        "New-RegistryItemProperty",

        # Azure Files AD domain join cmdlets
        "Get-AzStorageAccountADObject",
        "Get-AzStorageKerberosTicketStatus",
        "Test-AzStorageAccountADObjectPasswordIsKerbKey",
        "Update-AzStorageAccountADObjectPassword",
        "Join-AzStorageAccount", 
        "Invoke-AzStorageAccountADObjectPasswordRotation",
        "Update-AzStorageAccountAuthForAES256",

        # Azure Files debug cmdlets
        "Debug-AzStorageAccountAuth",
        "Debug-AzStorageAccountADDSAuth",
        "Debug-AzStorageAccountEntraKerbAuth",

        # General Azure cmdlets
        "Expand-AzResourceId",
        "Compress-AzResourceId",
        "Get-AzCurrentAzureADUser",
        "Test-AzPermission",
        "Assert-AzPermission",

        # DNS cmdlets
        "Confirm-AzDnsForwarderPreReqs",
        "Join-AzDnsForwarder",
        "Invoke-AzDnsForwarderDeployment",
        "Get-AzDnsForwarderIpAddress",
        "Update-AzVirtualNetworkDnsServers",
        "New-AzDnsForwarder",
        "New-AzDnsForwardingRuleSet",
        "Add-AzDnsForwardingRule",
        "Push-DnsServerConfiguration",

        #Share level permissions migration cmdlets
        "Move-OnPremSharePermissionsToAzureFileShare"
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = "*"
    
    # DSC resources to export from this module
    # DscResourcesToExport = @()
    
    # List of all modules packaged with this module
    # ModuleList = @()
    
    # List of all files packaged with this module
    # FileList = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        Config = @{
            AzurePrivateDnsIp = "168.63.129.16";
            DnsForwarderTemplateVersion = "0.1.0.0";
            DnsForwarderTemplate = "https://raw.githubusercontent.com/Azure-Samples/azure-files-samples/master/dns-forwarder/azuredeploy.json";
            SkipPowerShellGetCheck = $false;
            SkipAzPowerShellCheck = $false;
            SkipDotNetFrameworkCheck = $false
        };
    
        PSData = @{
    
            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()
    
            # A URL to the license for this module.
            # LicenseUri = ''
    
            # A URL to the main website for this project.
            # ProjectUri = ''
    
            # A URL to an icon representing this module.
            # IconUri = ''
    
            # ReleaseNotes of this module
            # ReleaseNotes = ''
    
        } # End of PSData hashtable
    
    } # End of PrivateData hashtable
    
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
    
    }
    
    
