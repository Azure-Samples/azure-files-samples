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
    'Az.Storage'     = '8.1.0'
}
