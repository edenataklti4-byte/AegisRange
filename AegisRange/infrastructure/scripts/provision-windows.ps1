# ==============================================================================
# AegisRange - Windows Target Node Provisioning Script
# Target Host : aegis-windows (Windows 10 Enterprise / 10.10.10.30)
#
# WARNING & DISCLAIMER:
# This script disables real-time antivirus defenses and enables extensive
# endpoint telemetry for malicious execution scenario analysis.
# FOR LAB AND EDUCATIONAL DETECTION ENGINEERING TRAINING ONLY.
# NEVER run this script on production systems.
# ==============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [*] Starting AegisRange Windows Target Provisioning..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Force TLS 1.2 for modern web downloads and repository connections
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------------------
# 1. Directory Structure Setup
# ------------------------------------------------------------------------------
$toolsDir = "C:\Tools"
if (!(Test-Path -Path $toolsDir)) {
    Write-Host "[+] Creating $toolsDir directory..." -ForegroundColor Green
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
}

# ------------------------------------------------------------------------------
# 2. Sysmon Telemetry Sensor Installation
# ------------------------------------------------------------------------------
$sysmonUrl = 'https://live.sysinternals.com/Sysmon64.exe'
$sysmonPath = "$toolsDir\Sysmon64.exe"
$configPath = "$toolsDir\sysmon-config.xml"

Write-Host "[+] Downloading Sysmon from Sysinternals..." -ForegroundColor Green
try {
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonPath -UseBasicParsing -TimeoutSec 60
} catch {
    Write-Warning "[-] Web download of Sysmon failed: $_. Retrying with WebClient..."
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($sysmonUrl, $sysmonPath)
}

if (Test-Path -Path $configPath) {
    Write-Host "[+] Installing Sysmon with configuration ($configPath)..." -ForegroundColor Green
    Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i `"$configPath`"" -Wait -NoNewWindow
} else {
    Write-Warning "[-] Sysmon configuration ($configPath) not found. Installing with default telemetry..."
    Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i" -Wait -NoNewWindow
}

# ------------------------------------------------------------------------------
# 3. PowerShell Auditing & Script Block Logging
# ------------------------------------------------------------------------------
Write-Host "[+] Configuring deep PowerShell telemetry..." -ForegroundColor Green

# Enable Script Block Logging (Event ID 4104)
$psScriptBlockPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if (!(Test-Path -Path $psScriptBlockPath)) {
    New-Item -Path $psScriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $psScriptBlockPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
Set-ItemProperty -Path $psScriptBlockPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 -Type DWord -Force

# Enable Module Logging (Event ID 4103)
$psModuleLoggingPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
if (!(Test-Path -Path $psModuleLoggingPath)) {
    New-Item -Path $psModuleLoggingPath -Force | Out-Null
}
Set-ItemProperty -Path $psModuleLoggingPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force

$moduleNamesPath = "$psModuleLoggingPath\ModuleNames"
if (!(Test-Path -Path $moduleNamesPath)) {
    New-Item -Path $moduleNamesPath -Force | Out-Null
}
Set-ItemProperty -Path $moduleNamesPath -Name '*' -Value '*' -Type String -Force

# ------------------------------------------------------------------------------
# 4. Advanced Windows Security Audit Policies
# ------------------------------------------------------------------------------
Write-Host "[+] Configuring Windows Security Subcategory Audit Policies..." -ForegroundColor Green

# Detailed Tracking: Process Creation (Event ID 4688) & Process Termination (4689)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

# Logon / Logoff tracking (Event IDs 4624, 4625, 4634, 4672)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Object Access: File System (Event ID 4663) & Registry
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Include Process Command Line in Event ID 4688
Write-Host "[+] Enabling command line auditing in Process Creation events..." -ForegroundColor Green
$auditSysPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (!(Test-Path -Path $auditSysPath)) {
    New-Item -Path $auditSysPath -Force | Out-Null
}
Set-ItemProperty -Path $auditSysPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force

# ------------------------------------------------------------------------------
# 5. Lab Environment Adjustments (Disable AV for Scenario Execution)
# ------------------------------------------------------------------------------
Write-Host "[+] Disabling Windows Defender real-time protection for controlled testing..." -ForegroundColor Yellow
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
} catch {
    Write-Warning "[-] Set-MpPreference encountered an issue: $_"
}

$defenderPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
if (!(Test-Path -Path $defenderPolicyPath)) {
    New-Item -Path $defenderPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $defenderPolicyPath -Name 'DisableAntiSpyware' -Value 1 -Type DWord -Force

# ------------------------------------------------------------------------------
# 6. Target User Account Creation
# ------------------------------------------------------------------------------
Write-Host "[+] Provisioning simulation user account 'labuser'..." -ForegroundColor Green
$existingUser = Get-LocalUser -Name "labuser" -ErrorAction SilentlyContinue
if (!$existingUser) {
    net user labuser 'LabPass123!' /add /comment:"AegisRange Simulation User"
    net localgroup Users labuser /add
    Write-Host "[+] Account 'labuser' created successfully." -ForegroundColor Green
} else {
    Write-Host "[-] User 'labuser' already exists. Resetting password..." -ForegroundColor Yellow
    net user labuser 'LabPass123!'
}

# ------------------------------------------------------------------------------
# 7. WinRM & Remote Management
# ------------------------------------------------------------------------------
Write-Host "[+] Enabling PowerShell Remoting & WinRM..." -ForegroundColor Green
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '10.10.10.10,10.10.10.*' -Force

# ------------------------------------------------------------------------------
# 8. Chocolatey & Python 3 Runtime (for Collector Agent)
# ------------------------------------------------------------------------------
Write-Host "[+] Installing Chocolatey package manager and Python 3..." -ForegroundColor Green
Set-ExecutionPolicy Bypass -Scope Process -Force
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    try {
        $installScript = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
        Invoke-Expression $installScript
    } catch {
        Write-Warning "[-] Chocolatey install failed: $_"
    }
}

if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco install python3 -y --no-progress
} else {
    Write-Warning "[-] Chocolatey unavailable, skipping automated python package install."
}

# ------------------------------------------------------------------------------
# 9. Windows Firewall Subnet Containment
# ------------------------------------------------------------------------------
Write-Host "[+] Configuring Windows Advanced Firewall network rules..." -ForegroundColor Green

# Remove conflicting demo rules if re-running
Remove-NetFirewallRule -DisplayName 'AegisRange - Allow Lab Subnet Inbound' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'AegisRange - Allow Lab Subnet Outbound' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'AegisRange - Block External Outbound' -ErrorAction SilentlyContinue

# Allow all inbound and outbound communication within 10.10.10.0/24
New-NetFirewallRule -DisplayName 'AegisRange - Allow Lab Subnet Inbound' `
    -Direction Inbound -Action Allow -RemoteAddress '10.10.10.0/24' -Profile Any

New-NetFirewallRule -DisplayName 'AegisRange - Allow Lab Subnet Outbound' `
    -Direction Outbound -Action Allow -RemoteAddress '10.10.10.0/24' -Profile Any

# Block outbound traffic outside the lab network (prevents unexpected external communication)
New-NetFirewallRule -DisplayName 'AegisRange - Block External Outbound' `
    -Direction Outbound -Action Block -RemoteAddress '!10.10.10.0/24' -Profile Any

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "[+] AegisRange Windows target provisioning complete." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
