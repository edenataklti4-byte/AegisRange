#!/bin/bash
# ==============================================================================
# AegisRange - VirtualBox Host-Only Network Setup Helper
#
# PURPOSE:
# Configures the isolated private host-only adapter for AegisRange:
#   - Subnet: 10.10.10.0/24
#   - Gateway / Host Adapter IP: 10.10.10.1
#   - Netmask: 255.255.255.0
#   - DHCP: DISABLED (All lab VMs use predictable static IP addresses)
#
# COMPATIBILITY:
# Works on Linux, macOS, and Windows (via Git Bash / WSL / MSYS2).
# On native Windows PowerShell, invoke VBoxManage.exe directly as noted below.
# ==============================================================================

set -euo pipefail

TARGET_IP="10.10.10.1"
TARGET_NETMASK="255.255.255.0"
NETWORK_CIDR="10.10.10.0/24"

echo "=================================================================="
echo " AegisRange: VirtualBox Host-Only Network Setup"
echo " Target Subnet: $NETWORK_CIDR | Host Gateway IP: $TARGET_IP"
echo "=================================================================="

# ------------------------------------------------------------------------------
# 1. Locate VBoxManage Binary
# ------------------------------------------------------------------------------
VBOX_BIN="VBoxManage"

if command -v VBoxManage &>/dev/null; then
    VBOX_BIN="VBoxManage"
elif command -v VBoxManage.exe &>/dev/null; then
    VBOX_BIN="VBoxManage.exe"
elif [ -f "/c/Program Files/Oracle/VirtualBox/VBoxManage.exe" ]; then
    VBOX_BIN="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
elif [ -f "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe" ]; then
    VBOX_BIN="C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"
elif [ -f "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe" ]; then
    VBOX_BIN="/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
else
    echo "[-] ERROR: VBoxManage was not found in PATH."
    echo "[!] If running on Windows, verify VirtualBox is installed at:"
    echo "    C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"
    echo "    Add that directory to your system PATH or execute from PowerShell:"
    echo "    & 'C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe' hostonlyif create"
    exit 1
fi

echo "[+] Using VirtualBox CLI: $($VBOX_BIN --version)"

# ------------------------------------------------------------------------------
# 2. Check If An Existing Host-Only Interface Matches 10.10.10.1
# ------------------------------------------------------------------------------
EXISTING_IF=""
echo "[*] Scanning existing VirtualBox host-only interfaces..."

# Read existing interfaces
HOST_IFS=$("$VBOX_BIN" list hostonlyifs 2>/dev/null || true)

if echo "$HOST_IFS" | grep -q "$TARGET_IP"; then
    # Extract interface name
    EXISTING_IF=$(echo "$HOST_IFS" | awk -v ip="$TARGET_IP" '
        /^Name:/ { name = substr($0, index($0,$2)) }
        /^IPAddress:/ && $2 == ip { print name; exit }
    ')
fi

IF_NAME=""

if [ -n "$EXISTING_IF" ]; then
    echo "[+] Found existing adapter already configured with $TARGET_IP: '$EXISTING_IF'"
    IF_NAME="$EXISTING_IF"
else
    echo "[*] Creating a new VirtualBox host-only interface..."
    CREATE_OUTPUT=$("$VBOX_BIN" hostonlyif create 2>&1)
    echo "$CREATE_OUTPUT"

    # Extract adapter name from output (e.g. "Interface 'vboxnet0' was successfully created" or "'VirtualBox Host-Only Ethernet Adapter #2'")
    IF_NAME=$(echo "$CREATE_OUTPUT" | sed -n "s/.*'\(.*\)'.*/\1/p" | head -n 1)

    if [ -z "$IF_NAME" ]; then
        echo "[-] Could not automatically parse interface name from output."
        echo "    Please verify with '$VBOX_BIN list hostonlyifs'."
        exit 1
    fi

    echo "[+] Successfully created interface: '$IF_NAME'"
    echo "[*] Assigning IP address $TARGET_IP and netmask $TARGET_NETMASK to '$IF_NAME'..."
    "$VBOX_BIN" hostonlyif ipconfig "$IF_NAME" --ip "$TARGET_IP" --netmask "$TARGET_NETMASK"
fi

# ------------------------------------------------------------------------------
# 3. Disable VirtualBox DHCP Server on Lab Subnet
# ------------------------------------------------------------------------------
# AegisRange uses explicit static IP assignments (10.10.10.10, 10.10.10.20, 10.10.10.30)
# to maintain predictable firewall policies and detection rules.
echo "[*] Ensuring VirtualBox DHCP server is disabled for '$IF_NAME'..."

# Attempt removal by interface name / network name
"$VBOX_BIN" dhcpserver remove --ifname "$IF_NAME" 2>/dev/null || true
"$VBOX_BIN" dhcpserver remove --netname "HostInterfaceNetworking-$IF_NAME" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 4. Verification & Output Summary
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo " [+] Host-Only Network Configuration Verified"
echo "=================================================================="
"$VBOX_BIN" list hostonlyifs | grep -A 8 -E "Name:.*$IF_NAME" || true

echo ""
echo "[✓] Subnet $NETWORK_CIDR is ready for AegisRange."
echo "[✓] You can now bring up the environment with:"
echo "    cd infrastructure && vagrant up"
