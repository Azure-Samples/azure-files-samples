# PowerShell script to update Entra ID app registrations
# Converts CIFS/<storageaccount>.file.core.windows.net to cifs/<storageaccount>.file.core.windows.net
# in the identifierUris property

#Requires -Modules Microsoft.Graph.Applications

param(
    [Parameter(Mandatory = $false)]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [string]$CsvFilePath,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

# Import required modules
Import-Module Microsoft.Graph.Applications -ErrorAction Stop

# Validate parameters
if (-not $AppId -and -not $CsvFilePath) {
    Write-Error "Either -AppId or -CsvFilePath parameter must be provided"
    exit 1
}

if ($AppId -and $CsvFilePath) {
    Write-Error "Only one of -AppId or -CsvFilePath parameters can be provided"
    exit 1
}

if ($CsvFilePath -and -not (Test-Path $CsvFilePath)) {
    Write-Error "CSV file not found: $CsvFilePath"
    exit 1
}

# Initialize output file if specified
$auditResults = @()
if ($OutputFile) {
    # Create output directory if it doesn't exist
    $outputDir = Split-Path $OutputFile -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    Write-Host "Audit results will be saved to: $OutputFile" -ForegroundColor Green
}

# Connect to Microsoft Graph (requires appropriate permissions)
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    if ($TenantId) {
        Write-Host "Using tenant ID: $TenantId" -ForegroundColor Gray
        Connect-MgGraph -Scopes "Application.ReadWrite.All" -TenantId $TenantId -ErrorAction Stop
    }
    else {
        Connect-MgGraph -Scopes "Application.ReadWrite.All" -ErrorAction Stop
    }
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

function Update-AppIdentifierUris {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Application
    )

    $updated = $false
    $originalUris = $Application.IdentifierUris
    $updatedUris = @()
    $auditRecord = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AppId = $Application.AppId
        DisplayName = $Application.DisplayName
        ObjectId = $Application.Id
        OriginalUris = $originalUris -join "; "
        UpdatedUris = ""
        ChangedUris = @()
        Status = ""
        ErrorMessage = ""
        WhatIfMode = $WhatIf.IsPresent
    }

    Write-Host "Processing app: $($Application.DisplayName)" -ForegroundColor Cyan
    Write-Host "App ID: $($Application.AppId)" -ForegroundColor Gray

    foreach ($uri in $originalUris) {
        # Check if the URI contains CIFS/<anything>.file.core.windows.net pattern
        if ($uri -match "CIFS/[^/]+\.file\.core\.windows\.net") {
            $newUri = $uri -replace "CIFS/", "cifs/"
            $updatedUris += $newUri
            $auditRecord.ChangedUris += [PSCustomObject]@{
                Original = $uri
                Updated = $newUri
            }
            Write-Host "  Found CIFS URI to update:" -ForegroundColor Yellow
            Write-Host "    Original: $uri" -ForegroundColor Red
            Write-Host "    Updated:  $newUri" -ForegroundColor Green
            $updated = $true
        }
        else {
            $updatedUris += $uri
            Write-Host "  Keeping URI unchanged: $uri" -ForegroundColor Gray
        }
    }

    $auditRecord.UpdatedUris = $updatedUris -join "; "

    if ($updated) {
        if ($WhatIf) {
            Write-Host "  [WHAT-IF] Would update identifier URIs for app: $($Application.DisplayName)" -ForegroundColor Magenta
            $auditRecord.Status = "Would Update (What-If)"
        }
        else {
            try {
                Write-Host "  Updating identifier URIs..." -ForegroundColor Yellow
                Update-MgApplication -ApplicationId $Application.Id -IdentifierUris $updatedUris
                Write-Host "  Successfully updated identifier URIs" -ForegroundColor Green
                $auditRecord.Status = "Updated Successfully"
            }
            catch {
                Write-Error "  Failed to update app $($Application.DisplayName): $_"
                $auditRecord.Status = "Update Failed"
                $auditRecord.ErrorMessage = $_.Exception.Message
            }
        }
    }
    else {
        Write-Host "  No CIFS URIs found to update" -ForegroundColor Gray
        $auditRecord.Status = "No Changes Needed"
    }

    Write-Host ""
    return $auditRecord
}

try {
    if ($AppId) {
        # Update specific app by App ID
        Write-Host "Searching for app with App ID: $AppId" -ForegroundColor Yellow
        $apps = Get-MgApplication -Filter "appId eq '$AppId'"

        if (-not $apps) {
            Write-Warning "No application found with App ID: $AppId"
            exit 1
        }
    }
    else {
        # Process apps from CSV file
        Write-Host "Reading app IDs from CSV file: $CsvFilePath" -ForegroundColor Yellow

        try {
            $csvData = Import-Csv $CsvFilePath

            # Validate CSV structure
            if (-not $csvData[0].PSObject.Properties.Name -contains "AppId") {
                Write-Error "CSV file must contain a column named 'AppId'"
                exit 1
            }

            $appIds = $csvData | Select-Object -ExpandProperty AppId | Where-Object { $_ -and $_.Trim() -ne "" }
            $totalApps = $appIds.Count

            Write-Host "Found $totalApps app IDs in CSV file" -ForegroundColor Green

            if ($totalApps -eq 0) {
                Write-Warning "No valid app IDs found in CSV file"
                exit 0
            }

            $apps = @()
            $processedCount = 0
            $notFoundCount = 0
            $batchSize = 50  # Process in batches to avoid overwhelming the API

            Write-Host "Processing apps in batches of $batchSize..." -ForegroundColor Yellow

            for ($i = 0; $i -lt $totalApps; $i += $batchSize) {
                $batch = $appIds[$i..([Math]::Min($i + $batchSize - 1, $totalApps - 1))]
                $batchNumber = [Math]::Floor($i / $batchSize) + 1
                $totalBatches = [Math]::Ceiling($totalApps / $batchSize)

                Write-Host "Processing batch $batchNumber of $totalBatches (Apps $($i + 1)-$([Math]::Min($i + $batchSize, $totalApps)))" -ForegroundColor Cyan

                foreach ($appId in $batch) {
                    $processedCount++
                    Write-Progress -Activity "Retrieving Applications" -Status "Processing app $processedCount of $totalApps" -PercentComplete (($processedCount / $totalApps) * 100)

                    try {
                        $app = Get-MgApplication -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
                        if ($app) {
                            $apps += $app
                        }
                        else {
                            $notFoundCount++
                            Write-Warning "App ID not found: $appId"
                        }
                    }
                    catch {
                        Write-Warning "Error retrieving app $appId`: $_"
                        $notFoundCount++
                    }

                    # Small delay to avoid rate limiting
                    Start-Sleep -Milliseconds 100
                }

                # Longer delay between batches
                if ($i + $batchSize -lt $totalApps) {
                    Write-Host "Waiting 2 seconds before next batch..." -ForegroundColor Gray
                    Start-Sleep -Seconds 2
                }
            }

            Write-Progress -Activity "Retrieving Applications" -Completed
            Write-Host "Successfully retrieved $($apps.Count) applications" -ForegroundColor Green

            if ($notFoundCount -gt 0) {
                Write-Warning "Could not find $notFoundCount app(s) from the CSV file"
            }
        }
        catch {
            Write-Error "Failed to process CSV file: $_"
            exit 1
        }
    }

    if ($apps.Count -eq 0) {
        Write-Warning "No applications found matching the criteria"
        exit 0
    }

    Write-Host "Found $($apps.Count) application(s) to process" -ForegroundColor Green
    Write-Host ""

    # Process each application with progress tracking
    $updateCount = 0
    $successCount = 0
    $failureCount = 0

    for ($i = 0; $i -lt $apps.Count; $i++) {
        $app = $apps[$i]
        Write-Progress -Activity "Updating Applications" -Status "Processing app $($i + 1) of $($apps.Count): $($app.DisplayName)" -PercentComplete ((($i + 1) / $apps.Count) * 100)

        # Track original counts before update
        $cifsUrisCount = ($app.IdentifierUris | Where-Object { $_ -match "CIFS/[^/]+\.file\.core\.windows\.net" }).Count

        try {
            $auditRecord = Update-AppIdentifierUris -Application $app
            $auditResults += $auditRecord
            $successCount++

            if ($cifsUrisCount -gt 0) {
                $updateCount++
            }
        }
        catch {
            Write-Error "Failed to process app $($app.DisplayName): $_"
            $failureCount++

            # Create audit record for failed processing
            $auditRecord = [PSCustomObject]@{
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                AppId = $app.AppId
                DisplayName = $app.DisplayName
                ObjectId = $app.Id
                OriginalUris = $app.IdentifierUris -join "; "
                UpdatedUris = ""
                ChangedUris = @()
                Status = "Processing Failed"
                ErrorMessage = $_.Exception.Message
                WhatIfMode = $WhatIf.IsPresent
            }
            $auditResults += $auditRecord
        }
    }

    Write-Progress -Activity "Updating Applications" -Completed

    # Summary report
    Write-Host "=== SUMMARY REPORT ===" -ForegroundColor Cyan
    Write-Host "Total applications processed: $($apps.Count)" -ForegroundColor White
    Write-Host "Applications with CIFS URIs updated: $updateCount" -ForegroundColor Green
    Write-Host "Applications processed successfully: $successCount" -ForegroundColor Green
    Write-Host "Applications that failed: $failureCount" -ForegroundColor $(if ($failureCount -gt 0) { "Red" } else { "Green" })

    if ($WhatIf) {
        Write-Host "Note: This was a WHAT-IF run - no actual changes were made" -ForegroundColor Magenta
    }

    # Export audit results if output file specified
    if ($OutputFile -and $auditResults.Count -gt 0) {
        Write-Host ""
        Write-Host "Exporting audit results to: $OutputFile" -ForegroundColor Yellow

        try {
            # Create detailed audit records with expanded changed URIs
            $detailedAuditResults = @()

            foreach ($record in $auditResults) {
                if ($record.ChangedUris.Count -gt 0) {
                    # Create separate records for each changed URI
                    foreach ($changedUri in $record.ChangedUris) {
                        $detailedRecord = [PSCustomObject]@{
                            Timestamp = $record.Timestamp
                            AppId = $record.AppId
                            DisplayName = $record.DisplayName
                            ObjectId = $record.ObjectId
                            OriginalUri = $changedUri.Original
                            UpdatedUri = $changedUri.Updated
                            AllOriginalUris = $record.OriginalUris
                            AllUpdatedUris = $record.UpdatedUris
                            Status = $record.Status
                            ErrorMessage = $record.ErrorMessage
                            WhatIfMode = $record.WhatIfMode
                        }
                        $detailedAuditResults += $detailedRecord
                    }
                }
                else {
                    # No changed URIs, create a single record
                    $detailedRecord = [PSCustomObject]@{
                        Timestamp = $record.Timestamp
                        AppId = $record.AppId
                        DisplayName = $record.DisplayName
                        ObjectId = $record.ObjectId
                        OriginalUri = ""
                        UpdatedUri = ""
                        AllOriginalUris = $record.OriginalUris
                        AllUpdatedUris = $record.UpdatedUris
                        Status = $record.Status
                        ErrorMessage = $record.ErrorMessage
                        WhatIfMode = $record.WhatIfMode
                    }
                    $detailedAuditResults += $detailedRecord
                }
            }

            # Export to CSV
            $detailedAuditResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

            Write-Host "Successfully exported $($detailedAuditResults.Count) audit record(s) to: $OutputFile" -ForegroundColor Green

            # Display summary of what was exported
            $exportedStatuses = $detailedAuditResults | Group-Object Status
            Write-Host ""
            Write-Host "Exported records by status:" -ForegroundColor Cyan
            foreach ($statusGroup in $exportedStatuses) {
                Write-Host "  $($statusGroup.Name): $($statusGroup.Count)" -ForegroundColor White
            }
        }
        catch {
            Write-Error "Failed to export audit results to $OutputFile`: $_"
        }
    }
    elseif ($OutputFile -and $auditResults.Count -eq 0) {
        Write-Host "No audit results to export" -ForegroundColor Yellow
    }

    Write-Host "Script completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Script failed: $_"
    exit 1
}
finally {
    # Disconnect from Microsoft Graph
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}