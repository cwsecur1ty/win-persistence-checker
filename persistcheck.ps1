# Windows Persistence Checker
# Checks various registry locations for persistence mechanisms

# Function to check registry keys and return findings
function Get-RegistryPersistence {
    $findings = @()
    
    # Common registry locations to check
    $registryPaths = @(
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Local Machine Run"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Local Machine RunOnce"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Current User Run"
        },
        @{
            Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Current User RunOnce"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Description = "Winlogon"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            Description = "Image File Execution Options"
        }
    )

    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath.Path) {
            $keys = Get-ItemProperty -Path $regPath.Path -ErrorAction SilentlyContinue
            if ($keys) {
                foreach ($key in $keys.PSObject.Properties) {
                    if ($key.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive')) {
                        $findings += [PSCustomObject]@{
                            Location = $regPath.Description
                            RegistryPath = $regPath.Path
                            Key = $key.Name
                            Value = $key.Value
                            LastWriteTime = (Get-ItemProperty -Path $regPath.Path).PSLastWriteTime
                        }
                    }
                }
            }
        }
    }

    return $findings
}

# Main execution
Write-Host "Windows Persistence Checker" -ForegroundColor Cyan
Write-Host "Checking registry locations for persistence mechanisms..." -ForegroundColor Yellow
Write-Host ""

$results = Get-RegistryPersistence

if ($results.Count -gt 0) {
    Write-Host "Found $($results.Count) potential persistence mechanisms:" -ForegroundColor Green
    $results | Format-Table -AutoSize
} else {
    Write-Host "No persistence mechanisms found in checked locations." -ForegroundColor Green
}

# Export to JSON if requested
$exportToJson = Read-Host "Would you like to export the results to JSON? (Y/N)"
if ($exportToJson -eq 'Y' -or $exportToJson -eq 'y') {
    $jsonPath = "persistence_findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $results | ConvertTo-Json | Out-File $jsonPath
    Write-Host "Results exported to $jsonPath" -ForegroundColor Green
} 