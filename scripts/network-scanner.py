#!/usr/bin/env python3
"""
ICS Network Security Scanner

A comprehensive network scanner designed specifically for Industrial Control Systems.
Discovers ICS devices, identifies protocols, and performs security assessments.

Author: Ali AlEnezi
Github: https://github.com/SiteQ8/ics-iot-ot-hardening/edit/main/scripts/network-scanner.py
License: MIT
Version: 1.0.0
"""

import socket
import struct
import threading
import time
import json
import argparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Information about discovered ICS device."""
    ip_address: str
    hostname: str
    mac_address: str
    vendor: str
    device_type: str
    protocols: List[str]
    firmware_version: str
    security_issues: List[str]

class ModbusScanner:
    """Modbus TCP protocol scanner."""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.default_port = 502
    
    def scan_device(self, ip: str, port: int = None) -> Optional[Dict]:
        """Scan device for Modbus TCP support."""
        port = port or self.default_port
        
        try:
            # Modbus TCP read holding registers request
            # Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0006
            # Unit ID: 0x01, Function: 0x03, Start: 0x0000, Quantity: 0x0001
            modbus_request = bytes.fromhex('000100000006010300000001')
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(modbus_request)
                
                response = sock.recv(1024)
                if len(response) >= 9 and response[7] == 0x03:
                    logger.info(f"Modbus device found at {ip}:{port}")
                    return {
                        'protocol': 'Modbus TCP',
                        'port': port,
                        'response_length': len(response),
                        'function_code': response[7]
                    }
        except Exception as e:
            logger.debug(f"Modbus scan failed for {ip}:{port} - {e}")
        
        return None

class DNP3Scanner:
    """DNP3 protocol scanner."""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.default_port = 20000
    
    def scan_device(self, ip: str, port: int = None) -> Optional[Dict]:
        """Scan device for DNP3 support."""
        port = port or self.default_port
        
        try:
            # DNP3 Link Layer Reset request
            dnp3_request = bytes.fromhex('0564050C04E98001000408')
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(dnp3_request)
                
                response = sock.recv(1024)
                if len(response) >= 5 and response[0:2] == bytes.fromhex('0564'):
                    logger.info(f"DNP3 device found at {ip}:{port}")
                    return {
                        'protocol': 'DNP3',
                        'port': port,
                        'response_length': len(response)
                    }
        except Exception as e:
            logger.debug(f"DNP3 scan failed for {ip}:{port} - {e}")
        
        return None

class EtherNetIPScanner:
    """EtherNet/IP protocol scanner."""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        self.default_port = 44818
    
    def scan_device(self, ip: str, port: int = None) -> Optional[Dict]:
        """Scan device for EtherNet/IP support."""
        port = port or self.default_port
        
        try:
            # EtherNet/IP List Services request
            enip_request = bytes.fromhex('010000000000000000000000000000000000000000000004')
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                sock.send(enip_request)
                
                response = sock.recv(1024)
                if len(response) >= 24:
                    logger.info(f"EtherNet/IP device found at {ip}:{port}")
                    return {
                        'protocol': 'EtherNet/IP',
                        'port': port,
                        'response_length': len(response)
                    }
        except Exception as e:
            logger.debug(f"EtherNet/IP scan failed for {ip}:{port} - {e}")
        
        return None

class ICSNetworkScanner:
    """Main ICS network scanner class."""
    
    def __init__(self, timeout: int = 3, threads: int = 50):
        self.timeout = timeout
        self.threads = threads
        self.scanners = {
            'modbus': ModbusScanner(timeout),
            'dnp3': DNP3Scanner(timeout),
            'enip': EtherNetIPScanner(timeout)
        }
        self.discovered_devices = []
    
    def generate_ip_range(self, cidr: str) -> List[str]:
        """Generate list of IP addresses from CIDR notation."""
        import ipaddress
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {cidr} - {e}")
            return []
    
    def check_host_alive(self, ip: str) -> bool:
        """Check if host is alive using TCP connect."""
        common_ports = [80, 443, 22, 23, 502, 20000, 44818]
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return True
            except:
                continue
        return False
    
    def scan_single_host(self, ip: str, protocols: List[str]) -> Optional[DeviceInfo]:
        """Scan single host for ICS protocols."""
        if not self.check_host_alive(ip):
            return None
        
        logger.info(f"Scanning {ip} for ICS protocols")
        
        device_info = DeviceInfo(
            ip_address=ip,
            hostname='',
            mac_address='',
            vendor='',
            device_type='',
            protocols=[],
            firmware_version='',
            security_issues=[]
        )
        
        # Try to resolve hostname
        try:
            device_info.hostname = socket.gethostbyaddr(ip)[0]
        except:
            device_info.hostname = 'Unknown'
        
        # Scan for each requested protocol
        for protocol in protocols:
            if protocol.lower() in self.scanners:
                scanner = self.scanners[protocol.lower()]
                result = scanner.scan_device(ip)
                if result:
                    device_info.protocols.append(result['protocol'])
        
        # Basic security checks
        if device_info.protocols:
            device_info.security_issues = self.basic_security_check(ip, device_info.protocols)
            return device_info
        
        return None
    
    def basic_security_check(self, ip: str, protocols: List[str]) -> List[str]:
        """Perform basic security checks on discovered device."""
        issues = []
        
        # Check for default credentials (simplified check)
        if 'Modbus TCP' in protocols:
            issues.append("Modbus TCP detected - ensure access controls are implemented")
        
        if 'DNP3' in protocols:
            issues.append("DNP3 detected - verify secure authentication is enabled")
        
        # Check for common vulnerabilities
        common_vuln_ports = [23, 80, 443, 21, 22]
        for port in common_vuln_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        if port == 23:
                            issues.append("Telnet service detected - consider secure alternatives")
                        elif port == 80:
                            issues.append("HTTP service detected - ensure HTTPS is used")
            except:
                continue
        
        return issues
    
    def scan_network(self, cidr: str, protocols: List[str] = None) -> List[DeviceInfo]:
        """Scan network range for ICS devices."""
        if protocols is None:
            protocols = ['modbus', 'dnp3', 'enip']
        
        ip_list = self.generate_ip_range(cidr)
        if not ip_list:
            logger.error("No valid IP addresses to scan")
            return []
        
        logger.info(f"Scanning {len(ip_list)} hosts for protocols: {protocols}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_single_host, ip, protocols) for ip in ip_list]
            
            for future in futures:
                try:
                    device = future.result()
                    if device:
                        self.discovered_devices.append(device)
                except Exception as e:
                    logger.error(f"Error scanning host: {e}")
        
        logger.info(f"Scan complete. Found {len(self.discovered_devices)} ICS devices")
        return self.discovered_devices
    
    def export_results(self, filename: str, format: str = 'json'):
        """Export scan results to file."""
        if not self.discovered_devices:
            logger.warning("No devices to export")
            return
        
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump([device.__dict__ for device in self.discovered_devices], f, indent=2)
        elif format.lower() == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Hostname', 'Protocols', 'Security Issues'])
                for device in self.discovered_devices:
                    writer.writerow([
                        device.ip_address,
                        device.hostname,
                        ','.join(device.protocols),
                        ','.join(device.security_issues)
                    ])
        
        logger.info(f"Results exported to {filename}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='ICS Network Security Scanner')
    parser.add_argument('target', help='Target network in CIDR notation (e.g., 192.168.1.0/24)')
    parser.add_argument('--protocols', '-p', nargs='+', 
                       choices=['modbus', 'dnp3', 'enip'], 
                       default=['modbus', 'dnp3', 'enip'],
                       help='Protocols to scan for')
    parser.add_argument('--threads', '-t', type=int, default=50, 
                       help='Number of threads to use')
    parser.add_argument('--timeout', type=int, default=3, 
                       help='Timeout for connections')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', '-f', choices=['json', 'csv'], default='json',
                       help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize scanner
    scanner = ICSNetworkScanner(timeout=args.timeout, threads=args.threads)
    
    # Perform scan
    devices = scanner.scan_network(args.target, args.protocols)
    
    # Display results
    if devices:
        print(f"\nFound {len(devices)} ICS devices:")
        print("-" * 80)
        for device in devices:
            print(f"IP: {device.ip_address}")
            print(f"Hostname: {device.hostname}")
            print(f"Protocols: {', '.join(device.protocols)}")
            if device.security_issues:
                print(f"Security Issues: {', '.join(device.security_issues)}")
            print("-" * 80)
    else:
        print("No ICS devices found")
    
    # Export results if requested
    if args.output:
        scanner.export_results(args.output, args.format)

if __name__ == "__main__":
    main()
