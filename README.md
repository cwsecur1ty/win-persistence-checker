# win-persistence-checker
A PowerShell-based tool to detect common Windows persistence mechanisms. Useful for malware analysis, incident response, or system audits.

---

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

---

## 💻 Usage

```powershell
.\persistcheck.ps1
```

Will implement -output feature.
