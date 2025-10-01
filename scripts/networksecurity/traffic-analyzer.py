#!/usr/bin/env python3
"""
ICS Traffic Analyzer

Protocol traffic analysis tool for Industrial Control Systems.
Analyzes network traffic for ICS protocols and detects anomalies.

Author: Ali AlEnezi
License: MIT
Version: 1.0.0
"""

import scapy.all as scapy
import argparse
import json
import logging
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import threading
import sqlite3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class TrafficStat:
    """Traffic statistics for a protocol."""
    protocol: str
    packet_count: int
    byte_count: int
    unique_sources: set
    unique_destinations: set
    first_seen: datetime
    last_seen: datetime
    anomaly_score: float = 0.0

class ICSProtocolAnalyzer:
    """Analyze ICS-specific protocols."""
    
    def __init__(self, db_path: str = "traffic_analysis.db"):
        self.db_path = db_path
        self.init_database()
        self.stats = defaultdict(lambda: TrafficStat(
            protocol="",
            packet_count=0,
            byte_count=0,
            unique_sources=set(),
            unique_destinations=set(),
            first_seen=datetime.now(),
            last_seen=datetime.now()
        ))
        self.baselines = {}
        self.anomaly_threshold = 2.0
    
    def init_database(self):
        """Initialize SQLite database for traffic storage."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                flags TEXT,
                payload_preview TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                anomaly_type TEXT,
                description TEXT,
                severity TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_modbus(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze Modbus TCP packets."""
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 502 or packet[scapy.TCP].sport == 502):
            tcp_layer = packet[scapy.TCP]
            
            # Basic Modbus TCP header analysis
            if len(packet[scapy.TCP].payload) >= 8:
                payload = bytes(packet[scapy.TCP].payload)
                
                # Modbus TCP ADU header
                transaction_id = int.from_bytes(payload[0:2], byteorder='big')
                protocol_id = int.from_bytes(payload[2:4], byteorder='big')
                length = int.from_bytes(payload[4:6], byteorder='big')
                unit_id = payload[6]
                function_code = payload[7] if len(payload) > 7 else 0
                
                analysis = {
                    'protocol': 'Modbus TCP',
                    'transaction_id': transaction_id,
                    'protocol_id': protocol_id,
                    'length': length,
                    'unit_id': unit_id,
                    'function_code': function_code,
                    'function_name': self._get_modbus_function_name(function_code)
                }
                
                # Check for anomalies
                if protocol_id != 0:
                    analysis['anomaly'] = f"Non-standard protocol ID: {protocol_id}"
                
                if function_code > 127:
                    analysis['anomaly'] = f"Exception response: {function_code - 128}"
                
                return analysis
        return None
    
    def analyze_dnp3(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze DNP3 packets."""
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 20000 or packet[scapy.TCP].sport == 20000):
            tcp_layer = packet[scapy.TCP]
            
            if len(packet[scapy.TCP].payload) >= 10:
                payload = bytes(packet[scapy.TCP].payload)
                
                # DNP3 Data Link Layer
                if payload[0:2] == b'\x05\x64':  # DNP3 start bytes
                    length = payload[2]
                    control = payload[3]
                    dest = int.from_bytes(payload[4:6], byteorder='little')
                    src = int.from_bytes(payload[6:8], byteorder='little')
                    
                    analysis = {
                        'protocol': 'DNP3',
                        'length': length,
                        'control': control,
                        'destination': dest,
                        'source': src,
                        'direction': 'master_to_outstation' if control & 0x80 else 'outstation_to_master'
                    }
                    
                    return analysis
        return None
    
    def analyze_ethernet_ip(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze EtherNet/IP packets."""
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 44818 or packet[scapy.TCP].sport == 44818):
            tcp_layer = packet[scapy.TCP]
            
            if len(packet[scapy.TCP].payload) >= 24:
                payload = bytes(packet[scapy.TCP].payload)
                
                # EtherNet/IP Encapsulation Header
                command = int.from_bytes(payload[0:2], byteorder='little')
                length = int.from_bytes(payload[2:4], byteorder='little')
                session_handle = int.from_bytes(payload[4:8], byteorder='little')
                status = int.from_bytes(payload[8:12], byteorder='little')
                
                analysis = {
                    'protocol': 'EtherNet/IP',
                    'command': command,
                    'command_name': self._get_enip_command_name(command),
                    'length': length,
                    'session_handle': session_handle,
                    'status': status
                }
                
                return analysis
        return None
    
    def analyze_opc_ua(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze OPC UA packets."""
        if packet.haslayer(scapy.TCP) and (packet[scapy.TCP].dport == 4840 or packet[scapy.TCP].sport == 4840):
            tcp_layer = packet[scapy.TCP]
            
            if len(packet[scapy.TCP].payload) >= 8:
                payload = bytes(packet[scapy.TCP].payload)
                
                # OPC UA Message Header
                if payload[0:3] == b'MSG':  # Message chunk
                    chunk_type = chr(payload[3])
                    message_size = int.from_bytes(payload[4:8], byteorder='little')
                    
                    analysis = {
                        'protocol': 'OPC UA',
                        'message_type': 'MSG',
                        'chunk_type': chunk_type,
                        'message_size': message_size
                    }
                    
                    return analysis
                elif payload[0:3] == b'HEL':  # Hello message
                    analysis = {
                        'protocol': 'OPC UA',
                        'message_type': 'Hello'
                    }
                    return analysis
        return None
    
    def _get_modbus_function_name(self, function_code: int) -> str:
        """Get Modbus function name from code."""
        function_names = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
            23: "Read/Write Multiple Registers"
        }
        return function_names.get(function_code, f"Unknown ({function_code})")
    
    def _get_enip_command_name(self, command: int) -> str:
        """Get EtherNet/IP command name from code."""
        command_names = {
            0x0001: "List Services",
            0x0004: "List Identity",
            0x0063: "List Interfaces",
            0x0065: "Register Session",
            0x0066: "UnRegister Session",
            0x006F: "Send RR Data",
            0x0070: "Send Unit Data"
        }
        return command_names.get(command, f"Unknown ({hex(command)})")
    
    def packet_handler(self, packet):
        """Handle captured packets."""
        timestamp = datetime.now()
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            packet_size = len(packet)
            
            # Analyze different ICS protocols
            analyses = []
            
            modbus_analysis = self.analyze_modbus(packet)
            if modbus_analysis:
                analyses.append(modbus_analysis)
            
            dnp3_analysis = self.analyze_dnp3(packet)
            if dnp3_analysis:
                analyses.append(dnp3_analysis)
            
            enip_analysis = self.analyze_ethernet_ip(packet)
            if enip_analysis:
                analyses.append(enip_analysis)
            
            opcua_analysis = self.analyze_opc_ua(packet)
            if opcua_analysis:
                analyses.append(opcua_analysis)
            
            # Update statistics and log to database
            for analysis in analyses:
                protocol = analysis['protocol']
                
                # Update statistics
                stat = self.stats[protocol]
                stat.protocol = protocol
                stat.packet_count += 1
                stat.byte_count += packet_size
                stat.unique_sources.add(src_ip)
                stat.unique_destinations.add(dst_ip)
                stat.last_seen = timestamp
                
                # Log to database
                self._log_to_database(timestamp, packet, analysis)
                
                # Check for anomalies
                if 'anomaly' in analysis:
                    self._log_anomaly(timestamp, analysis['anomaly'], 'HIGH', src_ip, dst_ip, protocol)
                
                # Print real-time analysis
                logger.info(f"{protocol}: {src_ip}:{getattr(packet[scapy.TCP], 'sport', 'N/A')} -> "
                          f"{dst_ip}:{getattr(packet[scapy.TCP], 'dport', 'N/A')}")
                
                if 'function_name' in analysis:
                    logger.info(f"  Function: {analysis['function_name']}")
                if 'command_name' in analysis:
                    logger.info(f"  Command: {analysis['command_name']}")
                if 'anomaly' in analysis:
                    logger.warning(f"  ANOMALY: {analysis['anomaly']}")
    
    def _log_to_database(self, timestamp: datetime, packet, analysis: Dict[str, Any]):
        """Log packet to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else ""
        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else ""
        src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else 0
        dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
        
        cursor.execute('''
            INSERT INTO traffic_logs 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, payload_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp.isoformat(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            analysis['protocol'],
            len(packet),
            str(packet[scapy.TCP].flags) if packet.haslayer(scapy.TCP) else "",
            str(analysis)[:500]
        ))
        
        conn.commit()
        conn.close()
    
    def _log_anomaly(self, timestamp: datetime, description: str, severity: str, src_ip: str, dst_ip: str, protocol: str):
        """Log anomaly to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO anomalies 
            (timestamp, anomaly_type, description, severity, src_ip, dst_ip, protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp.isoformat(),
            'Protocol Anomaly',
            description,
            severity,
            src_ip,
            dst_ip,
            protocol
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"ANOMALY DETECTED: {description}")
    
    def start_capture(self, interface: str, duration: int = None, packet_count: int = None):
        """Start packet capture."""
        logger.info(f"Starting packet capture on interface: {interface}")
        
        if duration:
            logger.info(f"Capture duration: {duration} seconds")
        if packet_count:
            logger.info(f"Capture count: {packet_count} packets")
        
        # Start capture
        scapy.sniff(
            iface=interface,
            prn=self.packet_handler,
            timeout=duration,
            count=packet_count,
            filter="tcp port 502 or tcp port 20000 or tcp port 44818 or tcp port 4840 or tcp port 102"
        )
    
    def analyze_pcap(self, pcap_file: str):
        """Analyze existing PCAP file."""
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        packets = scapy.rdpcap(pcap_file)
        for packet in packets:
            self.packet_handler(packet)
    
    def generate_report(self, output_file: str = None):
        """Generate traffic analysis report."""
        report = {
            'analysis_time': datetime.now().isoformat(),
            'protocols': {},
            'summary': {
                'total_protocols': len(self.stats),
                'total_packets': sum(stat.packet_count for stat in self.stats.values()),
                'total_bytes': sum(stat.byte_count for stat in self.stats.values())
            }
        }
        
        for protocol, stat in self.stats.items():
            report['protocols'][protocol] = {
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'unique_sources': len(stat.unique_sources),
                'unique_destinations': len(stat.unique_destinations),
                'first_seen': stat.first_seen.isoformat(),
                'last_seen': stat.last_seen.isoformat(),
                'anomaly_score': stat.anomaly_score
            }
        
        # Add anomaly summary
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM anomalies')
        anomaly_count = cursor.fetchone()[0]
        report['summary']['anomalies_detected'] = anomaly_count
        conn.close()
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to: {output_file}")
        else:
            print(json.dumps(report, indent=2))
        
        return report

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='ICS Traffic Analyzer')
    parser.add_argument('--interface', '-i', help='Network interface to capture from')
    parser.add_argument('--pcap', '-p', help='PCAP file to analyze')
    parser.add_argument('--duration', '-d', type=int, help='Capture duration in seconds')
    parser.add_argument('--count', '-c', type=int, help='Number of packets to capture')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--database', help='SQLite database file', default='traffic_analysis.db')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize analyzer
    analyzer = ICSProtocolAnalyzer(args.database)
    
    try:
        if args.pcap:
            # Analyze PCAP file
            analyzer.analyze_pcap(args.pcap)
        elif args.interface:
            # Live capture
            analyzer.start_capture(args.interface, args.duration, args.count)
        else:
            print("Error: Specify either --interface for live capture or --pcap for file analysis")
            return 1
        
        # Generate report
        analyzer.generate_report(args.output)
        
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
