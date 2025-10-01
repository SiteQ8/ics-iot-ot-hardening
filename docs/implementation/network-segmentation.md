# ICS Network Segmentation Guide (Purdue Model)

This guide provides step-by-step instructions and ready-to-use templates to implement secure network segmentation for Industrial Control Systems using the Purdue Enterprise Reference Architecture.

## 1. Architecture Overview

Purdue Levels:
- Level 5: Enterprise Network
- Level 4: Business LAN
- Level 3.5: ICS DMZ (Operations DMZ)
- Level 3: Site Operations (SCADA, Historians)
- Level 2: Area Supervisory Control (HMIs)
- Level 1: Basic Control (PLCs/RTUs)
- Level 0: Process (sensors/actuators)

## 2. Segmentation Principles

- Default-deny across zones; allow only necessary traffic
- ICS DMZ is the only bridge between Level 3 and Level 4/5
- No direct Level 4/5 to Level 2/1/0 communications
- Unidirectional gateways (data diodes) for one-way data flows when feasible
- Protocol-aware inspection at each boundary

## 3. Zone & Conduit Design

Reference zones:
- Z5: Enterprise (IT)
- Z4: Business (IT)
- Z3.5: ICS DMZ (bastion hosts, patch servers, AV mgmt, jump servers)
- Z3: Site Ops (SCADA server, Engineering Workstations, Historians)
- Z2: Area Control (HMIs)
- Z1: Basic Control (PLCs/RTUs)
- Z0: Process (field devices)

Conduits:
- C4-3.5: Enterprise to ICS DMZ (HTTPS, VPN only)
- C3.5-3: ICS DMZ to Site Ops (RDP/SSH via jump host, patch dist.)
- C3-2: Site Ops to Area Control (SCADA/HMI protocols)
- C2-1: Area to Basic Control (control protocols only)
- C1-0: Basic Control to Process (fieldbus as applicable)

## 4. Firewall Rule Templates

### 4.1 Z4 -> Z3.5 (Enterprise to ICS DMZ)
```
policy: default deny
allow: tcp/443 from Z4[Mgmt Subnets] to Z3.5[WSUS, AVMgmt]
allow: udp/500,udp/4500 from Z4[VPN GW] to Z3.5[VPN Term]
allow: tcp/22 from Z4[SecOps] to Z3.5[Jump Host] (MFA required)
log: all denies
inspect: TLS, IPsec
```

### 4.2 Z3.5 -> Z3 (ICS DMZ to Site Ops)
```
policy: default deny
allow: tcp/3389 from Z3.5[Jump Host] to Z3[Engineering WS] (RD Gateway)
allow: tcp/22 from Z3.5[Jump Host] to Z3[Linux Hosts]
allow: tcp/8530 from Z3.5[WSUS] to Z3[Windows]
allow: tcp/6514 from Z3[Syslog Senders] to Z3.5[SIEM Collector]
inspect: RDP, SSH, HTTP
log: all denies
```

### 4.3 Z3 -> Z2 (Site Ops to Area Control)
```
policy: default deny
allow: tcp/102 (IEC 61850 MMS) from SCADA to IEDs/HMIs
allow: tcp/4840 (OPC UA) from SCADA to HMIs
allow: tcp/1433 (SQL) from HMI to Historian (if required)
inspect: protocol-aware (MMS, OPC UA)
log: all denies
```

### 4.4 Z2 -> Z1 (Area Control to Basic Control)
```
policy: default deny
allow: tcp/502 (Modbus TCP) from HMI/SCADA to PLCs
allow: tcp/20000 (DNP3) from SCADA to RTUs
allow: udp/2222,tcp/44818 (EtherNet/IP CIP) from SCADA to PLCs
inspect: ICS protocol DPI
log: all denies
```

## 5. Remote Access Design

- VPN terminates in Z3.5 (ICS DMZ) only
- MFA for all remote sessions
- Use RD Gateway / SSH bastion
- Session recording and live monitoring
- Time-bound, approval-based access

## 6. Monitoring & Logging

- Central log collectors in Z3.5
- NetFlow/sFlow at each boundary
- Protocol-aware NIDS in Z3/Z2/Z1
- Baseline normal behavior; alert on deviation

## 7. Change Management

- Maintenance windows for rule changes
- Pre/post-change validation checklists
- Rollback plan with backups
- Documented approvals

## 8. Validation Checklist

- [ ] All default-deny policies enforced
- [ ] No direct Z4/Z5 to Z2/Z1 connectivity
- [ ] RDP/SSH only via jump hosts in Z3.5
- [ ] Logging for all denies and critical allows
- [ ] DPI enabled for ICS protocols
- [ ] Remote access uses MFA and recorded sessions
- [ ] Data diode applied where one-way flows are sufficient

## 9. Example Configs

Sample vendor-neutral pseudo-configs provided in `templates/firewall-rules/`.
