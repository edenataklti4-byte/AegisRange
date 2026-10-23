#!/bin/bash
# ==============================================================================
# AegisRange - Linux Target Node Provisioning Script
# Target Host : aegis-linux (Ubuntu Server 22.04 LTS / 10.10.10.20)
#
# WARNING & DISCLAIMER:
# This script configures an INTENTIONALLY VULNERABLE virtual machine environment
# containing weak credentials, exposed services, and relaxed security controls.
# FOR LAB AND EDUCATIONAL DETECTION ENGINEERING TRAINING ONLY.
# NEVER run this script on production systems or internet-exposed networks.
# ==============================================================================

set -euo pipefail

echo "[*] Starting AegisRange Linux target provisioning..."

# ------------------------------------------------------------------------------
# 1. System Package Updates
# ------------------------------------------------------------------------------
echo "[+] Updating apt repositories and packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# ------------------------------------------------------------------------------
# 2. SSH Server (Primary Brute-Force Target for Scenario 1)
# ------------------------------------------------------------------------------
echo "[+] Installing and configuring OpenSSH server..."
apt-get install -y openssh-server

# Deploy custom sshd_config if staged by Vagrant, otherwise edit in place
if [ -f /tmp/sshd_config ]; then
    echo "[+] Applying staged sshd_config template..."
    cp /tmp/sshd_config /etc/ssh/sshd_config
    chown root:root /etc/ssh/sshd_config
    chmod 644 /etc/ssh/sshd_config
else
    echo "[+] Modifying existing sshd_config..."
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    sed -i 's/^#MaxAuthTries.*/MaxAuthTries 100/' /etc/ssh/sshd_config
fi

systemctl restart sshd
systemctl enable sshd

# ------------------------------------------------------------------------------
# 3. vsftpd (Secondary FTP Target)
# ------------------------------------------------------------------------------
echo "[+] Installing and configuring vsftpd FTP server..."
apt-get install -y vsftpd

# Enable local user logins and write access
sed -i 's/^#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sed -i 's/^#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf

systemctl enable vsftpd
systemctl restart vsftpd

# ------------------------------------------------------------------------------
# 4. Auditd Telemetry & Kernel Auditing
# ------------------------------------------------------------------------------
echo "[+] Installing and configuring auditd for command telemetry..."
apt-get install -y auditd audispd-plugins

systemctl enable auditd
systemctl restart auditd

# Configure persistent audit rules for execution tracking
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/aegisrange.rules << 'EOF'
## AegisRange Audit Rules
# Track all 64-bit and 32-bit execve syscalls for command-line auditing
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution
EOF

# Load runtime audit rule
auditctl -a always,exit -F arch=b64 -S execve -k command_execution || true

# ------------------------------------------------------------------------------
# 5. User Accounts for Simulation
# ------------------------------------------------------------------------------
echo "[+] Provisioning lab user accounts with intentional credentials..."

# Lab user account (target for brute-force scenario)
if id "labuser" &>/dev/null; then
    echo "[-] User labuser already exists."
else
    useradd -m -s /bin/bash labuser
fi
echo 'labuser:labpass123' | chpasswd

# Admin account with predictable password for brute-force dictionaries
if id "admin" &>/dev/null; then
    echo "[-] User admin already exists."
else
    useradd -m -s /bin/bash admin
fi
echo 'admin:admin2024' | chpasswd

# ------------------------------------------------------------------------------
# 6. Logging Subsystem (rsyslog & auth.log)
# ------------------------------------------------------------------------------
echo "[+] Ensuring rsyslog is active for authentication event capture..."
apt-get install -y rsyslog
systemctl enable rsyslog
systemctl restart rsyslog

# ------------------------------------------------------------------------------
# 7. Utilities & Agent Dependencies
# ------------------------------------------------------------------------------
echo "[+] Installing diagnostic utilities and Python 3..."
apt-get install -y python3 python3-pip net-tools curl wget git tcpdump iproute2

# ------------------------------------------------------------------------------
# 8. Host Firewall Configuration (UFW)
# ------------------------------------------------------------------------------
echo "[+] Configuring UFW network containment..."
# Contain VM to training subnet (10.10.10.0/24) and block external outbound
apt-get install -y ufw
ufw --force reset
ufw default deny outgoing
ufw default allow incoming

# Allow all traffic to and from the isolated AegisRange subnet
ufw allow from 10.10.10.0/24
ufw allow to 10.10.10.0/24

# Allow DHCP for initial Vagrant NAT bootstrap if needed
ufw allow out to any port 67 proto udp
ufw allow in to any port 68 proto udp

ufw --force enable

echo "[+] AegisRange Linux target provisioning complete."
