# ---------------------------------------------------------------------------
# Script: Audit-SuspiciousTasks.ps1
# Description: Audit of scheduled tasks that can wake the PC or execute
#              scripts on non-commercial hours.
# Author: Murilo Henrique
# ---------------------------------------------------------------------------

Write-Host "--- Beginning Security Audit on Scheadules Tasks ---" -ForegroundColor Cyan

# 1. Search for tasks configured to "Wake the PC"
$WakeTasks = Get-ScheduledTask | Where-Object { $_.Settings.WakeToRun }

if ($WakeTasks) {
    Write-Host "[!] ALERT: Tasks found with 'Wake PC' permission:" -ForegroundColor Yellow
    $WakeTasks | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
} else {
    Write-Host "[+] No tasks found with wake-up configurations." -ForegroundColor Green
}

# 2. Search for tasks that start suspicious processes (PowerShell, CMD, Scripts)
$SuspiciousApps = "powershell.exe|cmd.exe|wscript.exe|cscript.exe|temp"
$SuspiciousTasks = Get-ScheduledTask | Where-Object { 
    $_.Actions.Execute -match $SuspiciousApps -or $_.Actions.Arguments -match $SuspiciousApps 
}

if ($SuspiciousTasks) {
    Write-Host "[!] WARNING: Task with script execution or command interpreters:" -ForegroundColor Cyan
    $SuspiciousTasks | Select-Object TaskName, @{Name="Command";Expression={$_.Actions.Execute}}, State | Format-Table -AutoSize
}

# 3. List tasks created in the last 7 days using Event Logs

$RecentDate = (Get-Date).AddDays(-7)
$OutputPath = "$HOME\Documents\TaskAudit_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"

Write-Host "[i] Starting log extraction... await." -ForegroundColor Cyan

# 3.1. Search on Security Event for task creation (ID 4698)
$SecurityEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4698
} -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $RecentDate }

# 3.2. Search for Operational event (100, 102, 106)
$OperationalEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    Id      = 100, 102, 106
} -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $RecentDate }

$AllEvents = $SecurityEvents + $OperationalEvents

# 3.3. Exportation
if ($AllEvents) {
    $AllEvents | Select-Object TimeCreated, Id, LogName, @{Name="Details"; Expression={$_.Message}} | 
    Sort-Object TimeCreated -Descending | 
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    
    Write-Host "[+] Success! Report created on: $OutputPath" -ForegroundColor Green
    Write-Host "[i] Total of events found: $($AllEvents.Count)" -ForegroundColor Gray
} else {
    Write-Host "[!] No task activity found." -ForegroundColor Yellow
}