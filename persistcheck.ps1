# Windows Persistence Checker
# =======================
#
# This PowerShell script is designed to help detect potential persistence mechanisms on Windows systems.
# It scans various registry locations commonly used for persistence and provides a detailed report of findings.
#
# What it checks:
# --------------
# 1. Common Run locations:
#    - Local Machine Run (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
#    - Current User Run (HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
#    - RunOnce entries for both Local Machine and Current User
#
# 2. System-level persistence:
#    - Winlogon entries
#    - Image File Execution Options (IFEO)
#    - Shell Execute Hooks
#    - Active Setup components
#
# 3. Policy-based persistence:
#    - Local Machine Policies Run
#    - Current User Policies Run
#
# Features:
# ---------
# - Severity-based classification (High, Medium, Low)
# - File existence validation for referenced executables
# - SHA256 hash calculation for referenced files
# - Color-coded output for quick visual assessment
# - JSON export capability for further analysis
# - Timestamp tracking for each finding
#
# Usage:
# ------
# Basic usage:
#   .\persistcheck.ps1
#
# Export to JSON:
#   .\persistcheck.ps1 -ExportJson
#
# Custom output path:
#   .\persistcheck.ps1 -ExportJson -OutputPath "C:\Reports\findings.json"
#
# Verbose output:
#   .\persistcheck.ps1 -VerboseOutput
#
# Output Format:
# -------------
# - Location: Friendly name of the registry location
# - RegistryPath: Full registry path
# - Key: Registry key name
# - Value: The actual value/command
# - Severity: Risk level (High/Medium/Low)
# - FileExists: Whether the referenced file exists
# - FileHash: SHA256 hash of the referenced file (if exists)
# - LastWriteTime: When the registry key was last modified
# - CheckTime: When the check was performed
#
# Author: https://github.com/cwsecur1ty

[CmdletBinding()]
param(
    [switch]$ExportJson,
    [string]$OutputPath = "persistence_findings_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$VerboseOutput
)

# Function to calculate SHA256 hash of a file
function Get-FileHash {
    param([string]$FilePath)
    
    try {
        if (Test-Path $FilePath) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
            return $hash.Hash
        }
    }
    catch {
        Write-Warning "Error calculating hash for $FilePath : $_"
    }
    return $null
}

# Function to extract file path from command
function Get-FilePathFromCommand {
    param([string]$Command)
    
    # Remove quotes if present
    $Command = $Command.Trim('"', "'")
    
    # Try to extract the first part of the command (usually the executable)
    if ($Command -match '^([a-zA-Z]:\\[^"\s]+)') {
        return $matches[1]
    }
    elseif ($Command -match '^([^"\s]+)') {
        return $matches[1]
    }
    
    return $null
}

# Function to validate file paths
function Test-FilePath {
    param([string]$Path)
    
    if ($Path -match '^[a-zA-Z]:\\') {
        return Test-Path $Path
    }
    return $false
}

# Function to determine severity level
function Get-SeverityLevel {
    param(
        [string]$Location,
        [string]$Value
    )
    
    # High severity indicators
    $highSeverityPatterns = @(
        'powershell.*bypass',
        'cmd.*\/c',
        'wscript.*\/e',
        'mshta',
        'regsvr32.*\/s',
        'rundll32.*\/s'
    )
    
    # Check for high severity patterns
    foreach ($pattern in $highSeverityPatterns) {
        if ($Value -match $pattern) {
            return "High"
        }
    }
    
    # Medium severity for non-standard locations
    if ($Location -match "RunOnce" -or $Location -match "Image File Execution Options") {
        return "Medium"
    }
    
    return "Low"
}

# Function to resolve file path (handles just the executable name by searching PATH)
function Resolve-FilePath {
    param([string]$FileName)
    if ([System.IO.Path]::IsPathRooted($FileName) -and (Test-Path $FileName)) {
        return $FileName
    }
    # If quoted, remove quotes
    $FileName = $FileName.Trim('"', "'")
    # Try to resolve via PATH and return the first match
    foreach ($dir in $env:PATH.Split(';')) {
        $candidate = Join-Path $dir $FileName
        if (Test-Path $candidate) { return $candidate }
    }
    return $FileName # fallback to original
}

# Function to check digital signature
function Get-DigitalSignatureInfo {
    param([string]$FilePath)
    $result = @{ IsSigned = $false; Signer = $null }
    try {
        if (Test-Path $FilePath) {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath
            if ($sig.Status -eq 'Valid') {
                $result.IsSigned = $true
                $result.Signer = $sig.SignerCertificate.Subject
            }
            elseif ($sig.Status -ne 'NotSigned') {
                $result.IsSigned = $false
                $result.Signer = $sig.Status
            }
        }
    }
    catch { }
    return $result
}

# Function for heuristic checks
function Get-HeuristicFlags {
    param([string]$FilePath)
    $flags = @()
    if ($FilePath) {
        # Suspicious if not in Windows or Program Files
        if ($FilePath -notmatch '^(C:\\Windows|C:\\Program Files)') {
            $flags += 'UnusualLocation'
        }
        # Suspicious if writable by non-admins
        try {
            $acl = Get-Acl $FilePath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.FileSystemRights -match 'Write' -and $ace.IdentityReference -notmatch 'BUILTIN\\Administrators') {
                    $flags += 'WritableByNonAdmin'
                    break
                }
            }
        }
        catch {}
        # Suspicious if double extension or typosquatting
        if ($FilePath -match '\\[^\\]+\.(exe|bat|cmd|vbs)\.(exe|bat|cmd|vbs)$') {
            $flags += 'DoubleExtension'
        }
        if ($FilePath -match 'svchost|explorer|lsass|csrss|winlogon' -and $FilePath -notmatch 'C:\\Windows') {
            $flags += 'TyposquatName'
        }
    }
    return $flags -join ','
}

# Function to check registry keys and return findings
function Get-RegistryPersistence {
    [CmdletBinding()]
    param()
    
    $findings = @()
    
    # Common registry locations to check
    $registryPaths = @(
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Local Machine Run"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Local Machine RunOnce"
        },
        @{
            Path        = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Description = "Current User Run"
        },
        @{
            Path        = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Description = "Current User RunOnce"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Description = "Winlogon"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            Description = "Image File Execution Options"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            Description = "Local Machine Policies Run"
        },
        @{
            Path        = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            Description = "Current User Policies Run"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
            Description = "Shell Execute Hooks"
        },
        @{
            Path        = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
            Description = "Active Setup"
        }
    )

    foreach ($regPath in $registryPaths) {
        try {
            if (Test-Path $regPath.Path) {
                $keys = Get-ItemProperty -Path $regPath.Path -ErrorAction Stop
                if ($keys) {
                    foreach ($key in $keys.PSObject.Properties) {
                        if ($key.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive')) {
                            $value = $key.Value
                            $filePathRaw = Get-FilePathFromCommand -Command $value
                            $filePath = Resolve-FilePath -FileName $filePathRaw
                            $fileExists = Test-Path $filePath
                            $fileHash = if ($fileExists) { Get-FileHash -FilePath $filePath } else { $null }
                            $sigInfo = if ($fileExists) { Get-DigitalSignatureInfo -FilePath $filePath } else { @{ IsSigned = $null; Signer = $null } }
                            $heuristics = if ($fileExists) { Get-HeuristicFlags -FilePath $filePath } else { $null }
                            $severity = Get-SeverityLevel -Location $regPath.Description -Value $value
                            
                            $findings += [PSCustomObject]@{
                                Location       = $regPath.Description
                                RegistryPath   = $regPath.Path
                                Key            = $key.Name
                                Value          = $value
                                Severity       = $severity
                                FileExists     = $fileExists
                                FilePath       = $filePath
                                FileHash       = $fileHash
                                IsSigned       = $sigInfo.IsSigned
                                Signer         = $sigInfo.Signer
                                HeuristicFlags = $heuristics
                                LastWriteTime  = (Get-ItemProperty -Path $regPath.Path).PSLastWriteTime
                                CheckTime      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Error checking $($regPath.Path): $_"
        }
    }

    return $findings
}

# Main execution
try {
    Write-Host "Windows Persistence Checker" -ForegroundColor Cyan
    Write-Host "Checking registry locations for persistence mechanisms..." -ForegroundColor Yellow
    Write-Host ""

    $results = Get-RegistryPersistence

    if ($results.Count -gt 0) {
        Write-Host "Found $($results.Count) potential persistence mechanisms:" -ForegroundColor Green
        
        # Group by severity
        $groupedResults = $results | Group-Object Severity
        foreach ($group in $groupedResults) {
            $color = switch ($group.Name) {
                "High" { "Red" }
                "Medium" { "Yellow" }
                "Low" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n$($group.Name) Severity Findings ($($group.Count)):" -ForegroundColor $color
            $group.Group | Format-Table -AutoSize
        }

        if ($ExportJson) {
            $results | ConvertTo-Json | Out-File $OutputPath
            Write-Host "`nResults exported to $OutputPath" -ForegroundColor Green
        }
    }
    else {
        Write-Host "No persistence mechanisms found in checked locations." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred during execution: $_"
    exit 1
} 