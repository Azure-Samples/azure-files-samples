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
    platyPS          = 'latest'
    'Az.Storage'     = '8.1.0'
    'Microsoft.Graph.Users' = '2.27.0'
    'Microsoft.Graph.Groups' = '2.27.0'
}
