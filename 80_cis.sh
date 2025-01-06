#!/bin/bash

set -e  # Exit on error
set -u  # Treat unset variables as an error

# Log file for the script
LOGFILE="/var/log/cis_hardening.log"
exec > >(tee -i $LOGFILE) 2>&1

echo "Starting CIS hardening..."

# Function to generate a report
generate_report() {
  local stage="$1"
  local report_file="/var/log/cis_${stage}_report.txt"
  echo "Generating ${stage} CIS report..."

  {
    echo "CIS Hardening ${stage} Report"
    echo "================================"

    echo "1. Mail Transfer Agent Configuration:"
    if command -v postfix &> /dev/null; then
      postconf | grep inet_interfaces
    else
      echo "Postfix not installed."
    fi

    echo "2. Unwanted Services:"
    services=("slapd" "named" "nfs-server" "avahi-daemon" "dhcp-server" "smbd" \
      "vsftpd" "nis" "cups" "rpcbind" "rsync" "snmpd" "xinetd")
    for service in "${services[@]}"; do
      systemctl is-enabled $service 2>/dev/null || echo "$service is not installed or disabled."
    done

    echo "3. Kernel Modules:"
    kernel_modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" \
      "dccp" "tipc" "rds" "sctp")
    for module in "${kernel_modules[@]}"; do
      lsmod | grep $module || echo "$module is not loaded."
    done

    echo "4. SSH Configuration:"
    sshd_config="/etc/ssh/sshd_config"
    grep -E "^(X11Forwarding|DisableForwarding|HostbasedAuthentication|IgnoreRhosts|LogLevel|MaxAuthTries|MaxStartups|PermitEmptyPasswords|PermitRootLogin|PermitUserEnvironment|UsePAM|AllowTcpForwarding)" $sshd_config

    echo "5. Mount Options:"
    grep -E "(/tmp|/dev/shm|/home)" /etc/fstab

    echo "6. Installed Packages:"
    dpkg -l | grep -E "(rsyslog|auditd|aide)"
  } > $report_file

  echo "${stage} report saved to $report_file"
}

# Generate pre-CIS report
generate_report "pre"

# Ensure mail transfer agent is configured for local-only mode
if command -v postfix &> /dev/null; then
  postconf -e "inet_interfaces = loopback-only"
  systemctl restart postfix
fi

# Ensure unwanted services are not installed
services=("slapd" "named" "nfs-server" "avahi-daemon" "dhcp-server" "smbd" \
  "vsftpd" "nis" "cups" "rpcbind" "rsync" "snmpd" "xinetd")

for service in "${services[@]}"; do
  if systemctl is-enabled $service &> /dev/null; then
    systemctl stop $service
    systemctl disable $service
  fi
  apt-get purge -y $service
done

# Ensure specific kernel modules are disabled
kernel_modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" \
  "dccp" "tipc" "rds" "sctp")

for module in "${kernel_modules[@]}"; do
  echo "install $module /bin/true" > /etc/modprobe.d/$module.conf
  modprobe -r $module || true
done

# Ensure cron daemon is enabled and running
systemctl enable cron
systemctl start cron

# Ensure sudo is installed
apt-get install -y sudo

# SSH configurations
SSHD_CONFIG="/etc/ssh/sshd_config"
ensure_sshd_option() {
  local option="$1"
  local value="$2"
  grep -q "^${option}" $SSHD_CONFIG && \
    sed -i "s/^${option}.*/${option} ${value}/" $SSHD_CONFIG || \
    echo "${option} ${value}" >> $SSHD_CONFIG
}

ensure_sshd_option "X11Forwarding" "no"
ensure_sshd_option "DisableForwarding" "yes"
ensure_sshd_option "HostbasedAuthentication" "no"
ensure_sshd_option "IgnoreRhosts" "yes"
ensure_sshd_option "LogLevel" "INFO"
ensure_sshd_option "MaxAuthTries" "4"
ensure_sshd_option "MaxStartups" "10:30:60"
ensure_sshd_option "PermitEmptyPasswords" "no"
ensure_sshd_option "PermitRootLogin" "no"
ensure_sshd_option "PermitUserEnvironment" "no"
ensure_sshd_option "UsePAM" "yes"
ensure_sshd_option "AllowTcpForwarding" "no"

systemctl restart sshd

# Ensure sudo commands use pty
echo "Defaults use_pty" >> /etc/sudoers

# Ensure sudo log file exists
echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers

# Ensure access to the su command is restricted
groupadd -f wheel
usermod -aG wheel root
chgrp wheel /bin/su
chmod 750 /bin/su

# Ensure /tmp, /dev/shm, and /home have secure mount options
secure_mount() {
  local partition="$1"
  local options="$2"
  if grep -q "$partition" /etc/fstab; then
    sed -i "/$partition/ s/defaults/defaults,$options/" /etc/fstab
  else
    echo "$partition defaults,$options 0 0" >> /etc/fstab
  fi
}

secure_mount /tmp "nodev,nosuid,noexec"
secure_mount /dev/shm "nodev,nosuid,noexec"
secure_mount /home "nodev"
mount -o remount /tmp
mount -o remount /dev/shm
mount -o remount /home

# Ensure required packages are installed
apt-get install -y rsyslog auditd aide
systemctl enable rsyslog
systemctl enable auditd

# Generate post-CIS report
generate_report "post"

echo "All CIS hardening steps completed successfully."
