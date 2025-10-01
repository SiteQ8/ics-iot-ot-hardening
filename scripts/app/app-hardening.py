#!/usr/bin/env python3
"""
ICS Application Hardening Tool

Automated security configuration tool for Industrial Control Systems applications.
Hardens SCADA, HMI, Historian, and other ICS software configurations.

Author: Ali AlEnezi
License: MIT
Version: 1.0.0
"""

import os
import json
import yaml
import argparse
import logging
import subprocess
import platform
import configparser
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import sqlite3
import winreg
import shutil
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ApplicationType(Enum):
    SCADA = "scada"
    HMI = "hmi"
    HISTORIAN = "historian"
    OPC_SERVER = "opc_server"
    ENGINEERING_WS = "engineering_workstation"
    FIREWALL = "firewall"
    ANTIVIRUS = "antivirus"

@dataclass
class HardeningResult:
    """Result of hardening operation."""
    application: str
    setting: str
    old_value: Any
    new_value: Any
    success: bool
    error_message: str = ""

class ICSApplicationHardener:
    """Main application hardening class."""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file) if config_file else self._default_config()
        self.results = []
        self.backup_dir = Path("./backups/app-configs")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load hardening configuration from file."""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default hardening configuration."""
        return {
            "scada": {
                "wonderware": {
                    "authentication": {
                        "enable_windows_auth": True,
                        "disable_anonymous": True,
                        "session_timeout": 1800
                    },
                    "network": {
                        "enable_encryption": True,
                        "disable_unnecessary_ports": True
                    }
                },
                "ignition": {
                    "authentication": {
                        "enable_2fa": True,
                        "password_complexity": True,
                        "session_timeout": 1800
                    },
                    "logging": {
                        "audit_level": "INFO",
                        "log_authentication": True
                    }
                }
            },
            "hmi": {
                "factorytalk": {
                    "security": {
                        "enable_user_lockout": True,
                        "lockout_attempts": 3,
                        "disable_guest_account": True
                    }
                },
                "wincc": {
                    "authentication": {
                        "enable_domain_auth": True,
                        "disable_local_accounts": True
                    }
                }
            },
            "historian": {
                "pi_system": {
                    "security": {
                        "enable_kerberos": True,
                        "disable_trust_all": True,
                        "enable_audit_trail": True
                    }
                },
                "wonderware_historian": {
                    "database": {
                        "enable_ssl": True,
                        "backup_encryption": True
                    }
                }
            },
            "opc": {
                "matrikon": {
                    "security": {
                        "enable_authentication": True,
                        "disable_anonymous": True,
                        "enable_encryption": True
                    }
                },
                "kepware": {
                    "security": {
                        "enable_user_manager": True,
                        "session_timeout": 900,
                        "enable_audit_log": True
                    }
                }
            }
        }
    
    def backup_configuration(self, app_name: str, config_path: str) -> bool:
        """Backup application configuration before hardening."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"{app_name}_{timestamp}.backup"
            
            if os.path.isfile(config_path):
                shutil.copy2(config_path, backup_file)
            elif os.path.isdir(config_path):
                shutil.copytree(config_path, backup_file)
            else:
                logger.warning(f"Configuration path not found: {config_path}")
                return False
                
            logger.info(f"Configuration backed up to: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
            return False
    
    def harden_wonderware_scada(self) -> List[HardeningResult]:
        """Harden Wonderware InTouch/System Platform."""
        results = []
        logger.info("Hardening Wonderware SCADA systems...")
        
        # Common Wonderware registry paths
        wonderware_paths = [
            r"SOFTWARE\Wonderware\InTouch",
            r"SOFTWARE\Wonderware\ArchestrA",
            r"SOFTWARE\Wonderware\System Platform"
        ]
        
        if platform.system() == "Windows":
            try:
                for reg_path in wonderware_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
                        
                        # Enable authentication logging
                        result = self._set_registry_value(
                            key, "EnableAuthLogging", 1, winreg.REG_DWORD,
                            "Wonderware", "Enable authentication logging"
                        )
                        results.append(result)
                        
                        # Set session timeout
                        result = self._set_registry_value(
                            key, "SessionTimeout", 1800, winreg.REG_DWORD,
                            "Wonderware", "Set session timeout to 30 minutes"
                        )
                        results.append(result)
                        
                        # Disable anonymous connections
                        result = self._set_registry_value(
                            key, "AllowAnonymous", 0, winreg.REG_DWORD,
                            "Wonderware", "Disable anonymous connections"
                        )
                        results.append(result)
                        
                        winreg.CloseKey(key)
                        
                    except FileNotFoundError:
                        logger.debug(f"Registry path not found: {reg_path}")
                        continue
                    except Exception as e:
                        logger.error(f"Error accessing registry path {reg_path}: {e}")
                        
            except Exception as e:
                logger.error(f"Error hardening Wonderware: {e}")
        
        return results
    
    def harden_ignition_scada(self) -> List[HardeningResult]:
        """Harden Inductive Automation Ignition."""
        results = []
        logger.info("Hardening Ignition SCADA system...")
        
        # Common Ignition installation paths
        ignition_paths = [
            Path("C:/Program Files/Inductive Automation/Ignition"),
            Path("C:/Program Files (x86)/Inductive Automation/Ignition")
        ]
        
        for ignition_path in ignition_paths:
            if ignition_path.exists():
                config_file = ignition_path / "data" / "gateway.xml"
                
                if config_file.exists():
                    # Backup configuration
                    self.backup_configuration("ignition", str(config_file))
                    
                    # Modify configuration (simplified XML manipulation)
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(config_file)
                        root = tree.getroot()
                        
                        # Enable audit logging
                        audit_elem = root.find(".//audit")
                        if audit_elem is not None:
                            audit_elem.set("enabled", "true")
                            audit_elem.set("level", "INFO")
                            
                            results.append(HardeningResult(
                                application="Ignition",
                                setting="Audit logging",
                                old_value="disabled",
                                new_value="enabled",
                                success=True
                            ))
                        
                        # Set session timeout
                        session_elem = root.find(".//session-timeout")
                        if session_elem is not None:
                            old_timeout = session_elem.text
                            session_elem.text = "1800"
                            
                            results.append(HardeningResult(
                                application="Ignition",
                                setting="Session timeout",
                                old_value=old_timeout,
                                new_value="1800",
                                success=True
                            ))
                        
                        # Save modified configuration
                        tree.write(config_file, encoding='utf-8', xml_declaration=True)
                        
                    except Exception as e:
                        logger.error(f"Error modifying Ignition config: {e}")
                        results.append(HardeningResult(
                            application="Ignition",
                            setting="Configuration",
                            old_value="",
                            new_value="",
                            success=False,
                            error_message=str(e)
                        ))
                break
        
        return results
    
    def harden_pi_system(self) -> List[HardeningResult]:
        """Harden OSIsoft PI System."""
        results = []
        logger.info("Hardening PI System...")
        
        # PI System registry paths
        pi_paths = [
            r"SOFTWARE\PISystem\PI",
            r"SOFTWARE\OSIsoft\PI"
        ]
        
        if platform.system() == "Windows":
            for reg_path in pi_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
                    
                    # Enable Kerberos authentication
                    result = self._set_registry_value(
                        key, "EnableKerberos", 1, winreg.REG_DWORD,
                        "PI System", "Enable Kerberos authentication"
                    )
                    results.append(result)
                    
                    # Disable trust for all users
                    result = self._set_registry_value(
                        key, "TrustAllUsers", 0, winreg.REG_DWORD,
                        "PI System", "Disable trust for all users"
                    )
                    results.append(result)
                    
                    # Enable audit trail
                    result = self._set_registry_value(
                        key, "EnableAuditTrail", 1, winreg.REG_DWORD,
                        "PI System", "Enable audit trail"
                    )
                    results.append(result)
                    
                    winreg.CloseKey(key)
                    break
                    
                except FileNotFoundError:
                    continue
                except Exception as e:
                    logger.error(f"Error hardening PI System: {e}")
        
        return results
    
    def harden_opc_servers(self) -> List[HardeningResult]:
        """Harden OPC servers (Matrikon, Kepware, etc.)."""
        results = []
        logger.info("Hardening OPC servers...")
        
        # OPC server configurations
        opc_configs = [
            {
                "name": "Matrikon OPC Server",
                "registry_path": r"SOFTWARE\Matrikon\OPC",
                "config_file": Path("C:/Program Files/Matrikon/OPC Server/MatrikonOPC.ini")
            },
            {
                "name": "Kepware",
                "registry_path": r"SOFTWARE\Kepware\KEPServerEX",
                "config_file": Path("C:/Program Files (x86)/Kepware/KEPServerEX/KEPServerEX.exe.config")
            }
        ]
        
        for opc_config in opc_configs:
            # Registry hardening
            if platform.system() == "Windows":
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, opc_config["registry_path"], 0, winreg.KEY_ALL_ACCESS)
                    
                    # Enable authentication
                    result = self._set_registry_value(
                        key, "EnableAuthentication", 1, winreg.REG_DWORD,
                        opc_config["name"], "Enable authentication"
                    )
                    results.append(result)
                    
                    # Disable anonymous access
                    result = self._set_registry_value(
                        key, "AllowAnonymous", 0, winreg.REG_DWORD,
                        opc_config["name"], "Disable anonymous access"
                    )
                    results.append(result)
                    
                    winreg.CloseKey(key)
                    
                except FileNotFoundError:
                    logger.debug(f"OPC server not found: {opc_config['name']}")
                except Exception as e:
                    logger.error(f"Error hardening {opc_config['name']}: {e}")
            
            # Configuration file hardening
            if opc_config["config_file"].exists():
                self.backup_configuration(opc_config["name"], str(opc_config["config_file"]))
                
                try:
                    # Read and modify configuration file
                    with open(opc_config["config_file"], 'r') as f:
                        content = f.read()
                    
                    # Apply security settings (example patterns)
                    modified = False
                    
                    if 'EnableSecurity="false"' in content:
                        content = content.replace('EnableSecurity="false"', 'EnableSecurity="true"')
                        modified = True
                        
                        results.append(HardeningResult(
                            application=opc_config["name"],
                            setting="Security enabled",
                            old_value="false",
                            new_value="true",
                            success=True
                        ))
                    
                    if modified:
                        with open(opc_config["config_file"], 'w') as f:
                            f.write(content)
                    
                except Exception as e:
                    logger.error(f"Error modifying {opc_config['name']} config: {e}")
        
        return results
    
    def harden_hmi_applications(self) -> List[HardeningResult]:
        """Harden HMI applications."""
        results = []
        logger.info("Hardening HMI applications...")
        
        # FactoryTalk View hardening
        if platform.system() == "Windows":
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Rockwell Software\RSView32", 0, winreg.KEY_ALL_ACCESS)
                
                # Enable user lockout
                result = self._set_registry_value(
                    key, "EnableUserLockout", 1, winreg.REG_DWORD,
                    "FactoryTalk View", "Enable user lockout"
                )
                results.append(result)
                
                # Set lockout attempts
                result = self._set_registry_value(
                    key, "LockoutAttempts", 3, winreg.REG_DWORD,
                    "FactoryTalk View", "Set lockout attempts to 3"
                )
                results.append(result)
                
                winreg.CloseKey(key)
                
            except FileNotFoundError:
                logger.debug("FactoryTalk View not found")
            except Exception as e:
                logger.error(f"Error hardening FactoryTalk View: {e}")
        
        # WinCC hardening
        wincc_path = Path("C:/Program Files/Siemens/WinCC")
        if wincc_path.exists():
            try:
                # WinCC configuration hardening
                config_file = wincc_path / "bin" / "WinCC.ini"
                if config_file.exists():
                    self.backup_configuration("WinCC", str(config_file))
                    
                    config = configparser.ConfigParser()
                    config.read(config_file)
                    
                    # Enable domain authentication
                    if 'Security' not in config:
                        config.add_section('Security')
                    
                    config.set('Security', 'EnableDomainAuth', '1')
                    config.set('Security', 'DisableLocalAccounts', '1')
                    
                    with open(config_file, 'w') as f:
                        config.write(f)
                    
                    results.append(HardeningResult(
                        application="WinCC",
                        setting="Domain authentication",
                        old_value="disabled",
                        new_value="enabled",
                        success=True
                    ))
                    
            except Exception as e:
                logger.error(f"Error hardening WinCC: {e}")
        
        return results
    
    def _set_registry_value(self, key, value_name: str, value_data: Any, value_type: int, 
                           app_name: str, description: str) -> HardeningResult:
        """Set Windows registry value."""
        try:
            # Get old value
            try:
                old_value, _ = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                old_value = None
            
            # Set new value
            winreg.SetValueEx(key, value_name, 0, value_type, value_data)
            
            return HardeningResult(
                application=app_name,
                setting=description,
                old_value=old_value,
                new_value=value_data,
                success=True
            )
            
        except Exception as e:
            return HardeningResult(
                application=app_name,
                setting=description,
                old_value=None,
                new_value=value_data,
                success=False,
                error_message=str(e)
            )
    
    def harden_database_connections(self) -> List[HardeningResult]:
        """Harden database connections used by ICS applications."""
        results = []
        logger.info("Hardening database connections...")
        
        # Common database connection strings locations
        config_locations = [
            Path("C:/Program Files/Common Files/ODBC/Data Sources"),
            Path("C:/Windows/System32/odbcad32.exe"),
            Path("C:/Windows/SysWOW64/odbcad32.exe")
        ]
        
        # SQL Server configuration hardening
        if platform.system() == "Windows":
            try:
                # SQL Server registry settings
                sql_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SOFTWARE\Microsoft\Microsoft SQL Server", 0, winreg.KEY_ALL_ACCESS)
                
                # Enable SQL Server authentication logging
                result = self._set_registry_value(
                    sql_key, "LoginAuditLevel", 3, winreg.REG_DWORD,
                    "SQL Server", "Enable comprehensive authentication logging"
                )
                results.append(result)
                
                winreg.CloseKey(sql_key)
                
            except FileNotFoundError:
                logger.debug("SQL Server not found")
            except Exception as e:
                logger.error(f"Error hardening SQL Server: {e}")
        
        return results
    
    def generate_hardening_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate comprehensive hardening report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_applications": len(set(result.application for result in self.results)),
            "total_settings": len(self.results),
            "successful_changes": len([r for r in self.results if r.success]),
            "failed_changes": len([r for r in self.results if not r.success]),
            "applications": {},
            "summary": {
                "success_rate": 0,
                "backup_location": str(self.backup_dir)
            }
        }
        
        # Group results by application
        for result in self.results:
            if result.application not in report["applications"]:
                report["applications"][result.application] = {
                    "settings_modified": 0,
                    "successful": 0,
                    "failed": 0,
                    "changes": []
                }
            
            app_report = report["applications"][result.application]
            app_report["settings_modified"] += 1
            
            if result.success:
                app_report["successful"] += 1
            else:
                app_report["failed"] += 1
            
            app_report["changes"].append({
                "setting": result.setting,
                "old_value": str(result.old_value),
                "new_value": str(result.new_value),
                "success": result.success,
                "error": result.error_message if not result.success else None
            })
        
        # Calculate success rate
        if self.results:
            report["summary"]["success_rate"] = (report["successful_changes"] / len(self.results)) * 100
        
        # Output report
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Hardening report saved to: {output_file}")
        
        return report
    
    def run_hardening(self, application_types: List[str] = None) -> None:
        """Run hardening for specified application types."""
        if not application_types:
            application_types = ["scada", "hmi", "historian", "opc", "database"]
        
        logger.info(f"Starting application hardening for: {', '.join(application_types)}")
        
        for app_type in application_types:
            try:
                if app_type.lower() == "scada":
                    self.results.extend(self.harden_wonderware_scada())
                    self.results.extend(self.harden_ignition_scada())
                
                elif app_type.lower() == "hmi":
                    self.results.extend(self.harden_hmi_applications())
                
                elif app_type.lower() == "historian":
                    self.results.extend(self.harden_pi_system())
                
                elif app_type.lower() == "opc":
                    self.results.extend(self.harden_opc_servers())
                
                elif app_type.lower() == "database":
                    self.results.extend(self.harden_database_connections())
                
                else:
                    logger.warning(f"Unknown application type: {app_type}")
                    
            except Exception as e:
                logger.error(f"Error hardening {app_type}: {e}")
        
        logger.info(f"Hardening completed. {len(self.results)} settings processed.")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='ICS Application Hardening Tool')
    parser.add_argument('--config', '-c', help='Configuration file (JSON/YAML)')
    parser.add_argument('--applications', '-a', nargs='+', 
                       choices=['scada', 'hmi', 'historian', 'opc', 'database'],
                       help='Application types to harden')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--backup-dir', help='Backup directory', default='./backups/app-configs')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be changed without making changes')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
        return
    
    # Initialize hardener
    hardener = ICSApplicationHardener(args.config)
    
    if args.backup_dir:
        hardener.backup_dir = Path(args.backup_dir)
        hardener.backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Run hardening
    hardener.run_hardening(args.applications)
    
    # Generate report
    report = hardener.generate_hardening_report(args.output)
    
    # Print summary
    print(f"\nHardening Summary:")
    print(f"Applications processed: {report['total_applications']}")
    print(f"Settings modified: {report['total_settings']}")
    print(f"Successful changes: {report['successful_changes']}")
    print(f"Failed changes: {report['failed_changes']}")
    print(f"Success rate: {report['summary']['success_rate']:.1f}%")
    print(f"Backups stored in: {report['summary']['backup_location']}")
    
    if report['failed_changes'] > 0:
        print(f"\nSome changes failed. Check the detailed report for more information.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
