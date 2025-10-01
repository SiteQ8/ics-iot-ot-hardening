#!/usr/bin/env bash
# Linux ICS System Hardening Script
# Author: Ali AlEnezi
# Version: 1.0.0
# Description: Hardens Linux systems for ICS/SCADA environments

set -euo pipefail
IFS=$'\n\t'

LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/linux-hardening-$(date +"%Y%m%d-%H%M%S").log"

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1"
}

require_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

backup_file() {
  local file="$1"
  local dest_dir="/var/backups/ics-hardening"
  mkdir -p "$dest_dir"
  if [[ -f "$file" ]]; then
    cp -a "$file" "$dest_dir/$(basename "$file").bak-$(date +"%Y%m%d")"
  fi
}

configure_firewall() {
  log "Configuring firewall (iptables/ufw) for ICS environment"
  if command -v ufw >/dev/null 2>&1; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    # Common ICS ports (adjust per role)
    ufw allow 22/tcp comment 'SSH (admin only)'
    ufw allow 502/tcp comment 'Modbus TCP'
    ufw allow 20000/tcp comment 'DNP3'
    ufw allow 102/tcp comment 'IEC 61850 MMS'
    ufw allow 4840/tcp comment 'OPC UA'
    ufw allow 44818/tcp comment 'EtherNet/IP'
    ufw --force enable
  else
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 502 -j ACCEPT
    iptables -A INPUT -p tcp --dport 20000 -j ACCEPT
    iptables -A INPUT -p tcp --dport 102 -j ACCEPT
    iptables -A INPUT -p tcp --dport 4840 -j ACCEPT
    iptables -A INPUT -p tcp --dport 44818 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4 || true
  fi
}

secure_sshd() {
  log "Hardening SSH daemon"
  backup_file /etc/ssh/sshd_config
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
  echo 'AllowGroups ics-admins' >> /etc/ssh/sshd_config
  systemctl restart sshd || systemctl restart ssh
}

apply_sysctl() {
  log "Applying kernel hardening settings"
  backup_file /etc/sysctl.conf
  cat >> /etc/sysctl.d/99-ics-hardening.conf <<'EOF'
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0

# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1

# Kernel protection
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
EOF
  sysctl --system
}

lockdown_services() {
  log "Disabling unnecessary services"
  systemctl disable --now avahi-daemon || true
  systemctl disable --now cups || true
  systemctl disable --now bluetooth || true
  systemctl disable --now rpcbind || true
  systemctl disable --now telnet || true
  systemctl disable --now tftp || true
}

auditd_config() {
  log "Configuring auditd for ICS"
  apt-get update -y || true
  apt-get install -y auditd audispd-plugins || true
  cat > /etc/audit/rules.d/ics-hardening.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/auth.log -p wa -k auth
-a always,exit -F arch=b64 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
EOF
  augenrules --load || true
  systemctl enable --now auditd
}

accounts_hardening() {
  log "Hardening accounts and authentication"
  apt-get install -y libpam-pwquality || true
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
  sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
  echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800 even_deny_root root_unlock_time=1800' > /etc/pam.d/common-auth.d/ics-lockout || true
}

update_policy() {
  log "Configuring update policy for controlled patching"
  if command -v apt-get >/dev/null 2>&1; then
    apt-mark hold '*linux*' || true
    sed -i 's/^APT::Periodic::Unattended-Upgrade.*/APT::Periodic::Unattended-Upgrade "0";/' /etc/apt/apt.conf.d/20auto-upgrades || true
  fi
}

report() {
  log "Generating hardening report"
  REPORT="./logs/linux-hardening-report-$(date +"%Y%m%d-%H%M%S").txt"
  {
    echo "System: $(hostnamectl 2>/dev/null | tr -s ' ')"
    echo "Kernel: $(uname -r)"
    echo "Firewall: $(ufw status 2>/dev/null || iptables -S 2>/dev/null)"
    echo "SSH config:"
    grep -E '^(PasswordAuthentication|PermitRootLogin|AllowGroups)' /etc/ssh/sshd_config || true
    echo "Audit rules:"
    auditctl -l 2>/dev/null || cat /etc/audit/rules.d/ics-hardening.rules 2>/dev/null || true
  } > "$REPORT"
  log "Report written to $REPORT"
}

main() {
  require_root
  configure_firewall
  secure_sshd
  apply_sysctl
  lockdown_services
  auditd_config
  accounts_hardening
  update_policy
  report
  log "Linux ICS hardening complete. Reboot recommended."
}

main "$@"
