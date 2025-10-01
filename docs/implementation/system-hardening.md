# ICS System Hardening Procedures

This document provides step-by-step procedures for hardening Windows and Linux hosts in ICS/SCADA environments while maintaining operational stability.

## 1. Pre-Hardening Preparation

- Create full system backup and snapshots
- Document system role, interfaces, and dependencies
- Identify required ICS protocols and ports
- Confirm maintenance window and rollback plan
- Notify stakeholders and operators

## 2. Windows Host Hardening

### 2.1 Baseline Security Configuration

- Apply latest vendor-recommended patches (offline WSUS if needed)
- Disable unnecessary services: Print Spooler, Fax, Remote Registry, Xbox services
- Enforce strong password policies: 12+ chars, complexity, 90-day rotation
- Enable auditing: Logon/Logoff, Account Management, Policy Change, Object Access
- Configure Windows Firewall: Default inbound deny; allow only required ICS ports

### 2.2 User Access Control

- Disable local administrator except break-glass
- Enforce UAC: EnableLUA=1, ConsentPromptBehaviorAdmin=2
- Implement least privilege and role-based access
- Remove unused local accounts; rename default admin

### 2.3 Application Control

- Enable AppLocker or WDAC for allow-listing ICS applications
- Block script interpreters except for admin tools
- Sign and verify all in-house ICS binaries

### 2.4 Logging and Monitoring

- Forward Windows Event Logs to central SIEM (TLS)
- Enable PowerShell logging (Module, Script Block, Transcription)
- Enable Sysmon with ICS-focused config

### 2.5 Remote Access

- RDP via RD Gateway in ICS DMZ only; MFA enforced
- Disable clipboard and drive redirection where possible
- Session recording for engineering accounts

## 3. Linux Host Hardening

### 3.1 Baseline Security

- Apply controlled patching; disable unattended upgrades
- Enforce firewall: default deny inbound, allow outbound
- Disable unused services: avahi, cups, bluetooth, rpcbind, telnet, tftp
- Apply kernel hardening: sysctl for rp_filter, redirects, ASLR, BPF

### 3.2 Authentication and Accounts

- Enforce SSH: no root login, key-based auth, allow ics-admins group only
- PAM policies: lockout after 5 failed attempts, password quality
- Sudo: require reason in logs, timestamp timeout minimal

### 3.3 Filesystem and Services

- Mount options: nodev,nosuid,noexec on /tmp,/var/tmp
- Enable auditd and critical file watches
- Configure NTP/chrony to trusted internal sources

### 3.4 Logging

- rsyslog to central collector over TCP/TLS (6514)
- Separate logs for ICS applications
- Log rotation and retention per policy

## 4. ICS Application Hardening

- Change all default credentials
- Disable unused protocols/modules
- Enforce RBAC within SCADA/Historian applications
- TLS for OPC UA; secure auth for DNP3 SAv5; MMS over TLS for IEC 61850
- Encrypt engineering project files; control access via versioning

## 5. Patch and Vulnerability Management

- Passive discovery for asset inventory
- Risk-based patching: test in dev, stage to standby, then production
- Maintenance windows and operator sign-off
- Tracking via change management system

## 6. Validation and Verification

- Pre/post-hardening checks against baseline
- Service health and performance validation
- Protocol communications tests for ICS paths
- Security controls verification: firewall rules, audit logs, authentication

## 7. Rollback Procedures

- Documented steps to revert registry, services, firewall
- Restore from backups if stability issues arise
- Post-rollback incident review

## 8. Compliance Mapping

- NIST SP 800-82 controls mapping
- ISA/IEC 62443 SR mapping
- Organization-specific policy alignment

## 9. Appendices

- Checklists for Windows/Linux hardening
- Sample Sysmon config for ICS
- Sample rsyslog TLS configuration
- Troubleshooting common ICS connectivity issues
