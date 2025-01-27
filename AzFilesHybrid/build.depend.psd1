# This file lists out development requirements for the module.
# For the runtime requirements, see the module manifest.
@{
    PSDependOptions  = @{
        Target    = 'bin\Dependencies'
        Install   = $true
        AddToPath = $true
    }

    Pester           = 'latest'
    PSScriptAnalyzer = 'latest'

    "Az.Accounts"  = "4.0.1"
    "Az.Compute"   = "9.0.1"
    "Az.Network"   = "7.12.0"
    "Az.Resources" = "7.8.0"
    "Az.Storage"   = "8.1.0"
    
    "Microsoft.Graph.Applications"                 = "2.2.0"
    "Microsoft.Graph.Authentication"               = "2.2.0"
    "Microsoft.Graph.Groups"                       = "2.2.0"
    "Microsoft.Graph.Identity.DirectoryManagement" = "2.2.0"
    "Microsoft.Graph.Identity.SignIns"             = "2.2.0"
    "Microsoft.Graph.Users"                        = "2.2.0"
    
    "PSStyle" = "1.1.8"
}
