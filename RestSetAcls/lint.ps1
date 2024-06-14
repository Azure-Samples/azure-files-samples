Invoke-ScriptAnalyzer -Path $PSScriptRoot\RestSetAcls -Severity Warning -Recurse -Outvariable issues
$errors   = $issues.Where({$_.Severity -eq 'Error'})
$warnings = $issues.Where({$_.Severity -eq 'Warning'})
if ($errors) {
    Write-Error "There were $($errors.Count) errors and $($warnings.Count) warnings total." -ErrorAction Stop
} else {
    Write-Output "There were $($errors.Count) errors and $($warnings.Count) warnings total."
}
