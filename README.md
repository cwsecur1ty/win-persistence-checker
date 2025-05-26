# win-persistence-checker
A PowerShell-based tool to detect common Windows persistence mechanisms. Useful for malware analysis, incident response, or system audits.

## Features

- Detects known persistence techniques including:
  - Registry `Run`, `RunOnce`, `Winlogon`, `Image File Execution Options`, etc.

Soon to add:
  - Scheduled Tasks and Startup folder entries
  - WMI Event Consumers
  - Services and Drivers with suspicious paths
  - AppInit_DLLs and known autostart locations
  - COM hijacking keys

- Outputs clean JSON or table format
- Lightweight, portable, and requires no external dependencies

## Installation & Usage Instructions

> ⚠️ These steps assume the machine may be compromised — do **not** directly browse GitHub on the infected system. Use PowerShell to fetch the script securely from a clean, trusted source.

### 1. Open PowerShell as Administrator
Right-click the Start menu → "Windows PowerShell (Admin)" or "Terminal (Admin)"

### 2. Download the Script Remotely via PowerShell
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/cwsecur1ty/win-persistence-checker/main/persistcheck.ps1" -OutFile "$env:USERPROFILE\Downloads\persistcheck.ps1"
```

### 3. Run the script
```powershell
Set-Location "$env:USERPROFILE\Downloads"
.\persistcheck.ps1
```

## Roadmap
- Add support for remote scanning via PowerShell Remoting
- Support output logging in JSON/CSV
- Add IOC signature detection
- VirusTotal/HybridAnalysis integration for hashes (optional)

License [LICENSE](LICENSE.md)
