# Changelog

## [2.0.0] - 2026-03-10

### Added
- Login screen with demo credentials (admin / ICS@Secure2025)
- Analyst role with read-only access (analyst / OT@View2025)
- User badge in header with logout functionality
- Asset Inventory tab — 15 demo ICS assets with:
  - PLCs (Siemens S7-1500, Allen-Bradley, Schneider M580)
  - RTUs (GE D400, ABB RTU560)
  - HMIs (Wonderware, Ignition)
  - Engineering Workstation, SCADA Server, Historian
  - OT Firewall, Industrial Switch, BMS, SIS, VFD
  - Vendor, firmware, IP, protocol, Purdue level, vulnerability status
- Incidents Timeline tab — 12 realistic ICS security incidents:
  - Unauthorized Modbus writes, S7comm auth bypass, SMBv1 detection
  - Port scans from IT to OT, BACnet discovery, firmware upload attempts
  - DNP3 DoS storms, expired TLS, unauthorized VPN, NTP drift
  - Color-coded severity (critical/high/medium/low)
- Dashboard expanded to 8 tabs (was 6)
- Author attribution throughout

### Changed
- Footer updated with full author name (Ali AlEnezi)
- Navigation supports 8 tabs

## [1.0.0] - 2025

### Initial Release
- 6-tab interactive GUI dashboard
- 1,247 security controls
- Security posture metrics
- Interactive Purdue Model
- Network topology visualization
- Firewall rule generator for ICS protocols
- Multi-standard compliance engine
- ICS vulnerability scanner (demo)
- 12 ICS protocol security reference
- CLI toolkit and Python scripts
- Docker deployment support
