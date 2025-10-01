#!/usr/bin/env python3
"""
ICS Firewall Rule Generator

Automatically generates firewall rules for ICS environments based on 
Purdue model architecture and security requirements.

Author: Ali AlEnezi
License: MIT
Version: 1.0.0
"""

import yaml
import json
import argparse
import logging
from typing import Dict, List, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleAction(Enum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"

@dataclass
class FirewallRule:
    """Firewall rule definition."""
    name: str
    source_zone: str
    destination_zone: str
    protocol: str
    port: str
    action: RuleAction
    description: str
    logging: bool = True

class ICSFirewallGenerator:
    """ICS-specific firewall rule generator."""
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.rules = []
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def generate_purdue_rules(self) -> List[FirewallRule]:
        """Generate rules based on Purdue model."""
        rules = []
        
        # Level 5 (Enterprise) to Level 3.5 (DMZ) rules
        rules.extend(self._generate_enterprise_to_dmz_rules())
        
        # Level 3.5 (DMZ) to Level 3 (Operations) rules
        rules.extend(self._generate_dmz_to_operations_rules())
        
        # Level 3 (Operations) to Level 2 (Area Control) rules
        rules.extend(self._generate_operations_to_area_rules())
        
        # Level 2 (Area Control) to Level 1 (Basic Control) rules
        rules.extend(self._generate_area_to_basic_rules())
        
        # Level 1 (Basic Control) to Level 0 (Process) rules
        rules.extend(self._generate_basic_to_process_rules())
        
        # Default deny rules
        rules.extend(self._generate_default_deny_rules())
        
        self.rules = rules
        return rules
    
    def _generate_enterprise_to_dmz_rules(self) -> List[FirewallRule]:
        """Generate rules for Enterprise to DMZ communication."""
        rules = []
        
        # HTTPS for patch management
        rules.append(FirewallRule(
            name="ENT_DMZ_HTTPS_PATCH",
            source_zone="L5_Enterprise",
            destination_zone="L3_5_DMZ",
            protocol="TCP",
            port="443",
            action=RuleAction.ALLOW,
            description="HTTPS for patch management systems",
            logging=True
        ))
        
        # VPN termination
        rules.append(FirewallRule(
            name="ENT_DMZ_VPN_IPSEC",
            source_zone="L5_Enterprise",
            destination_zone="L3_5_DMZ",
            protocol="UDP",
            port="500,4500",
            action=RuleAction.ALLOW,
            description="IPSec VPN termination",
            logging=True
        ))
        
        # SSH for jump host access (with MFA)
        rules.append(FirewallRule(
            name="ENT_DMZ_SSH_JUMP",
            source_zone="L5_Enterprise",
            destination_zone="L3_5_DMZ",
            protocol="TCP",
            port="22",
            action=RuleAction.ALLOW,
            description="SSH to jump host (MFA required)",
            logging=True
        ))
        
        return rules
    
    def _generate_dmz_to_operations_rules(self) -> List[FirewallRule]:
        """Generate rules for DMZ to Operations communication."""
        rules = []
        
        # RDP via jump host
        rules.append(FirewallRule(
            name="DMZ_OPS_RDP_JUMP",
            source_zone="L3_5_DMZ",
            destination_zone="L3_Operations",
            protocol="TCP",
            port="3389",
            action=RuleAction.ALLOW,
            description="RDP via jump host to engineering workstations",
            logging=True
        ))
        
        # SSH for Linux systems
        rules.append(FirewallRule(
            name="DMZ_OPS_SSH",
            source_zone="L3_5_DMZ",
            destination_zone="L3_Operations",
            protocol="TCP",
            port="22",
            action=RuleAction.ALLOW,
            description="SSH to Linux systems in operations",
            logging=True
        ))
        
        # WSUS for Windows updates
        rules.append(FirewallRule(
            name="DMZ_OPS_WSUS",
            source_zone="L3_5_DMZ",
            destination_zone="L3_Operations",
            protocol="TCP",
            port="8530,8531",
            action=RuleAction.ALLOW,
            description="WSUS for Windows updates",
            logging=True
        ))
        
        # Syslog collection
        rules.append(FirewallRule(
            name="OPS_DMZ_SYSLOG",
            source_zone="L3_Operations",
            destination_zone="L3_5_DMZ",
            protocol="TCP",
            port="6514",
            action=RuleAction.ALLOW,
            description="Syslog forwarding to SIEM",
            logging=False
        ))
        
        return rules
    
    def _generate_operations_to_area_rules(self) -> List[FirewallRule]:
        """Generate rules for Operations to Area Control communication."""
        rules = []
        
        # IEC 61850 MMS
        rules.append(FirewallRule(
            name="OPS_AREA_IEC61850",
            source_zone="L3_Operations",
            destination_zone="L2_Area",
            protocol="TCP",
            port="102",
            action=RuleAction.ALLOW,
            description="IEC 61850 MMS communication",
            logging=True
        ))
        
        # OPC UA
        rules.append(FirewallRule(
            name="OPS_AREA_OPCUA",
            source_zone="L3_Operations",
            destination_zone="L2_Area",
            protocol="TCP",
            port="4840",
            action=RuleAction.ALLOW,
            description="OPC UA communication",
            logging=True
        ))
        
        # SQL Server for historians
        rules.append(FirewallRule(
            name="AREA_OPS_SQL",
            source_zone="L2_Area",
            destination_zone="L3_Operations",
            protocol="TCP",
            port="1433",
            action=RuleAction.ALLOW,
            description="SQL Server historian access",
            logging=True
        ))
        
        return rules
    
    def _generate_area_to_basic_rules(self) -> List[FirewallRule]:
        """Generate rules for Area Control to Basic Control communication."""
        rules = []
        
        # Modbus TCP
        rules.append(FirewallRule(
            name="AREA_BASIC_MODBUS",
            source_zone="L2_Area",
            destination_zone="L1_Basic",
            protocol="TCP",
            port="502",
            action=RuleAction.ALLOW,
            description="Modbus TCP communication",
            logging=True
        ))
        
        # DNP3
        rules.append(FirewallRule(
            name="AREA_BASIC_DNP3",
            source_zone="L2_Area",
            destination_zone="L1_Basic",
            protocol="TCP",
            port="20000",
            action=RuleAction.ALLOW,
            description="DNP3 communication",
            logging=True
        ))
        
        # EtherNet/IP
        rules.append(FirewallRule(
            name="AREA_BASIC_ENIP",
            source_zone="L2_Area",
            destination_zone="L1_Basic",
            protocol="TCP,UDP",
            port="44818,2222",
            action=RuleAction.ALLOW,
            description="EtherNet/IP CIP communication",
            logging=True
        ))
        
        return rules
    
    def _generate_basic_to_process_rules(self) -> List[FirewallRule]:
        """Generate rules for Basic Control to Process communication."""
        rules = []
        
        # Fieldbus protocols (context-specific)
        if self.config.get('fieldbus', {}).get('profinet', False):
            rules.append(FirewallRule(
                name="BASIC_PROCESS_PROFINET",
                source_zone="L1_Basic",
                destination_zone="L0_Process",
                protocol="TCP,UDP",
                port="34962,34963,34964",
                action=RuleAction.ALLOW,
                description="PROFINET communication",
                logging=False
            ))
        
        if self.config.get('fieldbus', {}).get('devicenet', False):
            rules.append(FirewallRule(
                name="BASIC_PROCESS_DEVICENET",
                source_zone="L1_Basic",
                destination_zone="L0_Process",
                protocol="UDP",
                port="2222",
                action=RuleAction.ALLOW,
                description="DeviceNet communication",
                logging=False
            ))
        
        return rules
    
    def _generate_default_deny_rules(self) -> List[FirewallRule]:
        """Generate default deny rules for all zones."""
        rules = []
        zones = ["L5_Enterprise", "L3_5_DMZ", "L3_Operations", "L2_Area", "L1_Basic", "L0_Process"]
        
        for src_zone in zones:
            for dst_zone in zones:
                if src_zone != dst_zone:
                    rules.append(FirewallRule(
                        name=f"DEFAULT_DENY_{src_zone}_TO_{dst_zone}",
                        source_zone=src_zone,
                        destination_zone=dst_zone,
                        protocol="ANY",
                        port="ANY",
                        action=RuleAction.DENY,
                        description=f"Default deny from {src_zone} to {dst_zone}",
                        logging=True
                    ))
        
        return rules
    
    def export_to_format(self, format_type: str, output_file: str) -> None:
        """Export rules to specified format."""
        if format_type.lower() == 'json':
            self._export_to_json(output_file)
        elif format_type.lower() == 'csv':
            self._export_to_csv(output_file)
        elif format_type.lower() == 'palo_alto':
            self._export_to_palo_alto(output_file)
        elif format_type.lower() == 'checkpoint':
            self._export_to_checkpoint(output_file)
        elif format_type.lower() == 'fortinet':
            self._export_to_fortinet(output_file)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _export_to_json(self, output_file: str) -> None:
        """Export rules to JSON format."""
        rules_data = []
        for rule in self.rules:
            rules_data.append({
                'name': rule.name,
                'source_zone': rule.source_zone,
                'destination_zone': rule.destination_zone,
                'protocol': rule.protocol,
                'port': rule.port,
                'action': rule.action.value,
                'description': rule.description,
                'logging': rule.logging
            })
        
        with open(output_file, 'w') as f:
            json.dump(rules_data, f, indent=2)
        
        logger.info(f"Rules exported to JSON: {output_file}")
    
    def _export_to_csv(self, output_file: str) -> None:
        """Export rules to CSV format."""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'Source Zone', 'Destination Zone', 'Protocol', 'Port', 'Action', 'Description', 'Logging'])
            
            for rule in self.rules:
                writer.writerow([
                    rule.name,
                    rule.source_zone,
                    rule.destination_zone,
                    rule.protocol,
                    rule.port,
                    rule.action.value,
                    rule.description,
                    rule.logging
                ])
        
        logger.info(f"Rules exported to CSV: {output_file}")
    
    def _export_to_palo_alto(self, output_file: str) -> None:
        """Export rules to Palo Alto format."""
        with open(output_file, 'w') as f:
            f.write("# Palo Alto Networks Firewall Rules\n")
            f.write("# Generated by ICS Firewall Rule Generator\n\n")
            
            for rule in self.rules:
                if rule.action == RuleAction.ALLOW:
                    f.write(f"set rulebase security rules {rule.name} from {rule.source_zone}\n")
                    f.write(f"set rulebase security rules {rule.name} to {rule.destination_zone}\n")
                    f.write(f"set rulebase security rules {rule.name} source any\n")
                    f.write(f"set rulebase security rules {rule.name} destination any\n")
                    f.write(f"set rulebase security rules {rule.name} service service-{rule.protocol.lower()}-{rule.port}\n")
                    f.write(f"set rulebase security rules {rule.name} action allow\n")
                    if rule.logging:
                        f.write(f"set rulebase security rules {rule.name} log-start yes\n")
                    f.write(f"set rulebase security rules {rule.name} description \"{rule.description}\"\n\n")
        
        logger.info(f"Rules exported to Palo Alto format: {output_file}")
    
    def _export_to_checkpoint(self, output_file: str) -> None:
        """Export rules to Check Point format."""
        with open(output_file, 'w') as f:
            f.write("# Check Point Firewall Rules\n")
            f.write("# Generated by ICS Firewall Rule Generator\n\n")
            
            for rule in self.rules:
                action = "accept" if rule.action == RuleAction.ALLOW else "drop"
                log = "log" if rule.logging else ""
                f.write(f"# {rule.description}\n")
                f.write(f"fwrule -a -n {rule.name} -s {rule.source_zone} -d {rule.destination_zone} ")
                f.write(f"-p {rule.protocol.lower()} -port {rule.port} -{action} {log}\n\n")
        
        logger.info(f"Rules exported to Check Point format: {output_file}")
    
    def _export_to_fortinet(self, output_file: str) -> None:
        """Export rules to Fortinet FortiGate format."""
        with open(output_file, 'w') as f:
            f.write("# Fortinet FortiGate Firewall Rules\n")
            f.write("# Generated by ICS Firewall Rule Generator\n\n")
            
            rule_id = 1
            for rule in self.rules:
                if rule.action == RuleAction.ALLOW:
                    f.write(f"config firewall policy\n")
                    f.write(f"    edit {rule_id}\n")
                    f.write(f"        set name \"{rule.name}\"\n")
                    f.write(f"        set srcintf \"{rule.source_zone}\"\n")
                    f.write(f"        set dstintf \"{rule.destination_zone}\"\n")
                    f.write(f"        set srcaddr \"all\"\n")
                    f.write(f"        set dstaddr \"all\"\n")
                    f.write(f"        set action accept\n")
                    f.write(f"        set service \"{rule.protocol}-{rule.port}\"\n")
                    if rule.logging:
                        f.write(f"        set logtraffic all\n")
                    f.write(f"        set comments \"{rule.description}\"\n")
                    f.write(f"    next\n")
                    f.write(f"end\n\n")
                    rule_id += 1
        
        logger.info(f"Rules exported to Fortinet format: {output_file}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='ICS Firewall Rule Generator')
    parser.add_argument('config', help='Configuration file (YAML)')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'palo_alto', 'checkpoint', 'fortinet'], 
                       default='json', help='Output format')
    parser.add_argument('--output', '-o', required=True, help='Output file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize generator
    generator = ICSFirewallGenerator(args.config)
    
    # Generate rules
    rules = generator.generate_purdue_rules()
    
    logger.info(f"Generated {len(rules)} firewall rules")
    
    # Export rules
    generator.export_to_format(args.format, args.output)
    
    print(f"Firewall rules generated and exported to: {args.output}")
    print(f"Total rules: {len(rules)}")
    
    # Summary by action
    allow_count = sum(1 for rule in rules if rule.action == RuleAction.ALLOW)
    deny_count = sum(1 for rule in rules if rule.action == RuleAction.DENY)
    
    print(f"Allow rules: {allow_count}")
    print(f"Deny rules: {deny_count}")

if __name__ == "__main__":
    main()
