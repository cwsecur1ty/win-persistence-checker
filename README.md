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

## Installation Instructions

## 💻 Usage

```powershell
.\persistcheck.ps1
```

## Roadmap
- Add support for remote scanning via PowerShell Remoting
- Support output logging in JSON/CSV
- Add IOC signature detection
- VirusTotal/HybridAnalysis integration for hashes (optional)

License [LICENSE](LICENSE.md)
