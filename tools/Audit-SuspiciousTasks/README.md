# Audit-SuspiciousTasks.ps1

## Description
This script automates the audit of Windows Scheduled Tasks to identify potential security persistence vectors. In Industrial Control Systems (ICS) and SCADA environments, attackers frequently leverage the Windows Task Scheduler to execute malicious code or maintain unauthorized access to Engineering Workstations (EWS).

## Key Features
- **Event Correlation**: Cross-references Security Event ID 4698 (Task Creation) with Operational Event IDs 100, 102, and 106 (Lifecycle Tracking).
- **Automated Reporting**: Exports all identified activities into a CSV format, optimized for further forensic analysis in SIEM platforms or Excel.
- **Persistence Detection**: Designed to highlight tasks created or executed within a specified timeframe, facilitating the detection of unauthorized modifications.

## Requirements
- **OS**: Windows 10/11 or Windows Server 2016/2019/2022.
- **Privileges**: Must be executed with **Administrator** privileges to read protected system logs.
- **Log Configuration**: The `Microsoft-Windows-TaskScheduler/Operational` log must be enabled in the Event Viewer for full visibility.

## Usage
1. Open PowerShell as an Administrator.
2. Navigate to the script directory.
3. Run the script:
   ```powershell
   .\Audit-SuspiciousTasks.ps1 

## Observation
Depending of the language of your OS, some tweaks in code are necessary.