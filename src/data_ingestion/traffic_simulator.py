# src/data_ingestion/traffic_simulator.py
import os
import time
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import ipaddress
import threading
import logging

class TrafficSimulator:
    """Generate realistic network traffic data including normal and anomalous patterns."""
   
    def __init__(self, output_dir="../data/raw"):
        """Initialize TrafficSimulator."""
        self.output_dir = output_dir
        self.running = False
        self.thread = None
       
        # Configure logging
        logging.basicConfig(level=logging.INFO,
                           format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
       
        # Network parameters
        self.internal_networks = ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
        self.external_networks = ["203.0.113.0/24", "198.51.100.0/24", "104.16.0.0/12"]
       
        # Traffic patterns
        self.protocols = {
            'HTTP': {'ports': [80, 8080], 'weight': 35},
            'HTTPS': {'ports': [443, 8443], 'weight': 40},
            'DNS': {'ports': [53], 'weight': 20},
            'SMTP': {'ports': [25, 587], 'weight': 5},
            'SSH': {'ports': [22], 'weight': 10},
            'FTP': {'ports': [20, 21], 'weight': 5},
            'TELNET': {'ports': [23], 'weight': 1},
            'RDP': {'ports': [3389], 'weight': 5},
            'SMB': {'ports': [445], 'weight': 5},
            'SNMP': {'ports': [161, 162], 'weight': 3},
            'NTP': {'ports': [123], 'weight': 3},
            'DHCP': {'ports': [67, 68], 'weight': 3},
            'ICMP': {'ports': [0], 'weight': 5},
            'TLS': {'ports': [443], 'weight': 15},
            'UDP': {'ports': [53, 123, 161, 1900], 'weight': 10},
            'TCP': {'ports': [80, 443, 22, 21, 25], 'weight': 30}
        }
       
        # Attack patterns
        self.attack_types = {
            'port_scan': {
                'weight': 20,
                'frequency': 0.05,
                'pattern': 'many_ports'
            },
            'ddos': {
                'weight': 10,
                'frequency': 0.02,
                'pattern': 'high_volume'
            },
            'data_exfiltration': {
                'weight': 15,
                'frequency': 0.03,
                'pattern': 'large_outbound'
            },
            'brute_force': {
                'weight': 25,
                'frequency': 0.04,
                'pattern': 'repeated_auth'
            },
            'malware_c2': {
                'weight': 15,
                'frequency': 0.03,
                'pattern': 'unusual_port'
            },
            'suspicious_dns': {
                'weight': 15,
                'frequency': 0.03,
                'pattern': 'dns_tunnel'
            }
        }
       
        # Packet size parameters
        self.packet_size_min = 64
        self.packet_size_max = 1500
       
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
   
    def _get_random_ip(self, network):
        """Get a random IP from a network."""
        net = ipaddress.ip_network(network)
        # Convert to int and get a random host
        host_bits = 32 - net.prefixlen
        if host_bits <= 0:
            return str(net.network_address)
       
        random_host = random.randint(1, (2 ** host_bits) - 2)
        random_ip = net.network_address + random_host
        return str(random_ip)
   
    def generate_ip(self, internal=True):
        """Generate a random IP address using either method."""
        if random.random() < 0.7:
            # Use CIDR method
            if internal:
                network = random.choice(self.internal_networks)
            else:
                network = random.choice(self.external_networks)
            return self._get_random_ip(network)
        else:
            # Use the simpler octet method
            if internal:
                prefix = random.choice(['10.0.0.', '192.168.1.', '172.16.0.'])
                suffix = random.randint(1, 254)
                return f"{prefix}{suffix}"
            else:
                return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
   
    def _get_weighted_choice(self, choices_dict):
        """Get a weighted random choice from a dictionary."""
        choices = list(choices_dict.keys())
        weights = [choices_dict[c]['weight'] for c in choices]
        return random.choices(choices, weights=weights, k=1)[0]
   
    def generate_timestamp(self, start_time=None, end_time=None):
        """Generate a random timestamp within the given range."""
        if start_time is None:
            start_time = datetime.now() - timedelta(minutes=5)
        if end_time is None:
            end_time = datetime.now()
       
        delta = end_time - start_time
        int_delta = int(delta.total_seconds())
        random_second = random.randint(0, int_delta)
        return start_time + timedelta(seconds=random_second)
   
    def _generate_normal_packet(self, timeframe=3600):
        """Generate a single normal network packet."""
        # Generate timestamp within the timeframe
        end_time = datetime.now()
        start_time = end_time - timedelta(seconds=timeframe)
        timestamp = start_time + timedelta(seconds=random.uniform(0, timeframe))
       
        # Decide if internal->external or external->internal
        if random.random() < 0.7:  # 70% internal->external
            src_ip = self.generate_ip(internal=True)
            dst_ip = self.generate_ip(internal=False)
        else:  # 30% external->internal
            src_ip = self.generate_ip(internal=False)
            dst_ip = self.generate_ip(internal=True)
       
        # Select protocol and corresponding port
        protocol = self._get_weighted_choice(self.protocols)
        dst_port = random.choice(self.protocols[protocol]['ports'])
        src_port = random.randint(10000, 65535)
       
        # Generate packet length based on protocol
        if protocol in ['HTTP', 'HTTPS', 'FTP', 'SMB']:
            # These can have larger packets
            length = random.randint(200, self.packet_size_max)
        elif protocol in ['DNS', 'SNMP', 'NTP', 'ICMP']:
            # These typically have smaller packets
            length = random.randint(self.packet_size_min, 300)
        else:
            # Medium sized packets
            length = random.randint(100, 800)
       
        # TTL values typically between 32-128
        ttl = random.choice([32, 64, 128])
       
        return {
            'timestamp': timestamp.timestamp(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': length,
            'ttl': ttl,
            'tcp_flags': random.randint(0, 63) if protocol in ['HTTP', 'HTTPS', 'SSH', 'SMTP', 'FTP', 'TCP', 'TLS'] else None,
            'attack_type': 'normal'
        }
   
    def _generate_normal_traffic(self, num_records=100, timeframe=3600):
        """Generate normal traffic patterns."""
        records = []
       
        for _ in range(num_records):
            records.append(self._generate_normal_packet(timeframe))
           
        return pd.DataFrame(records)
   
    def _generate_port_scan(self, num_records=50):
        """Generate port scan attack pattern."""
        records = []
       
        # Port scan typically comes from a single source to multiple destination ports
        timestamp = datetime.now().timestamp()
        src_ip = self.generate_ip(internal=False)
        dst_ip = self.generate_ip(internal=True)
       
        # Generate multiple packets to different ports
        port_range = list(range(20, 1000)) + list(range(3000, 3500))
        scan_ports = random.sample(port_range, min(num_records, len(port_range)))
       
        for i, port in enumerate(scan_ports):
            # Port scans happen in rapid succession
            scan_timestamp = timestamp + (i * 0.01)  # 10ms between packets
           
            records.append({
                'timestamp': scan_timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(10000, 65535),
                'dst_port': port,
                'protocol': 'TCP',
                'length': random.randint(40, 100),  # Scan packets are usually small
                'ttl': 64,
                'tcp_flags': 2,  # SYN flag
                'attack_type': 'port_scan'
            })
       
        return pd.DataFrame(records)
   
    def _generate_ddos_attack(self, num_records=200):
        """Generate DDoS attack pattern."""
        records = []
       
        # DDoS typically involves many packets to a single destination
        timestamp = datetime.now().timestamp()
        dst_ip = self.generate_ip(internal=True)
        dst_port = random.choice([80, 443, 8080, 22])  # Common targeted ports
       
        # Generate packets from multiple source IPs (distributed DDoS)
        for i in range(num_records):
            # DDoS attacks happen very rapidly
            attack_timestamp = timestamp + (i * 0.001)  # 1ms between packets
           
            # Use multiple source IPs for a DDoS
            src_ip = self.generate_ip(internal=False)
           
            records.append({
                'timestamp': attack_timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(10000, 65535),
                'dst_port': dst_port,
                'protocol': 'TCP',
                'length': random.randint(1000, self.packet_size_max),  # DDoS often uses larger packets
                'ttl': 64,
                'tcp_flags': random.choice([2, 18, 16]),  # SYN, SYN-ACK, ACK
                'attack_type': 'ddos'
            })
       
        return pd.DataFrame(records)
   
    def _generate_data_exfiltration(self, num_records=30):
        """Generate data exfiltration pattern."""
        records = []
       
        # Data exfiltration is typically from internal to external
        timestamp = datetime.now().timestamp()
        src_ip = self.generate_ip(internal=True)
        dst_ip = self.generate_ip(internal=False)
       
        # Often uses unusual ports or encrypted protocols
        dst_port = random.choice([6667, 4444, 8443, 8080, 9001])
       
        # Create a series of large outbound packets
        for i in range(num_records):
            # Data exfiltration happens in bursts
            exfil_timestamp = timestamp + (i * random.uniform(0.5, 2.0))
           
            records.append({
                'timestamp': exfil_timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(10000, 65535),
                'dst_port': dst_port,
                'protocol': random.choice(['TCP', 'HTTP', 'HTTPS']),
                'length': random.randint(1200, self.packet_size_max),  # Exfiltration uses large packets
                'ttl': 64,
                'tcp_flags': 16,  # ACK flag
                'attack_type': 'data_exfiltration'
            })
       
        return pd.DataFrame(records)
   
    def _generate_brute_force(self, num_records=100):
        """Generate brute force attack pattern."""
        records = []
       
        # Brute force typically targets authentication services
        timestamp = datetime.now().timestamp()
        src_ip = self.generate_ip(internal=False)
        dst_ip = self.generate_ip(internal=True)
        dst_port = random.choice([22, 3389, 5900, 23, 445])  # SSH, RDP, VNC, Telnet, SMB
       
        protocol = {
            22: 'SSH',
            3389: 'RDP',
            5900: 'VNC',
            23: 'TELNET',
            445: 'SMB'
        }.get(dst_port, 'TCP')
       
        # Generate repeated login attempts
        for i in range(num_records):
            # Brute force attempts happen at regular intervals
            bf_timestamp = timestamp + (i * random.uniform(0.5, 2.0))
           
            records.append({
                'timestamp': bf_timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(10000, 65535),
                'dst_port': dst_port,
                'protocol': protocol,
                'length': random.randint(100, 500),
                'ttl': 64,
                'tcp_flags': 16,  # ACK flag
                'attack_type': 'brute_force'
            })
       
        return pd.DataFrame(records)
   
    def _generate_malware_c2(self, num_records=40):
        """Generate malware command and control traffic pattern."""
        records = []
       
        # C2 involves beaconing from internal to external
        timestamp = datetime.now().timestamp()
        src_ip = self.generate_ip(internal=True)
       
        # C2 servers often use uncommon ports
        dst_ports = [random.randint(10000, 65000), 8080, 443, 53, 6666, 4444, 31337, 12345, 54321]
        dst_ip = self.generate_ip(internal=False)
       
        # Generate beaconing pattern
        for i in range(num_records):
            # C2 beaconing happens at regular intervals
            c2_timestamp = timestamp + (i * random.uniform(30, 300))  # 30s to 5min
           
            records.append({
                'timestamp': c2_timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(10000, 65535),
                'dst_port': random.choice(dst_ports),
                'protocol': random.choice(['TCP', 'HTTP', 'HTTPS', 'DNS']),
                'length': random.randint(60, 200),  # Beacons are typically small
                'ttl': 64,
                'tcp_flags': 16,  # ACK flag
                'attack_type': 'malware_c2'
            })
       
        return pd.DataFrame(records)
   
    def _generate_suspicious_dns(self, num_records=30):
        """Generate suspicious DNS traffic pattern."""
        records = []
       
        # Suspicious DNS may involve DGA domains or DNS tunneling
        timestamp = datetime.now().timestamp()
        src_ip = self.generate_ip(internal=True)
       
        # DNS servers or malicious DNS endpoints
        dst_ips = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            self.generate_ip(internal=False)
        ]
       
        # Generate unusual DNS traffic
        for i in range(num_records):
            # DNS queries happen periodically
            dns_timestamp = timestamp + (i * random.uniform(1, 10))
           
            # DNS tunneling has larger than normal packets
            if random.random() < 0.5:
                length = random.randint(300, 500)  # Larger packets for tunneling
            else:
                length = random.randint(60, 120)  # Normal DNS queries
           
            records.append({
                'timestamp': dns_timestamp,
                'src_ip': src_ip,
                'dst_ip': random.choice(dst_ips),
                'src_port': random.randint(10000, 65535),
                'dst_port': 53,
                'protocol': 'DNS',
                'length': length,
                'ttl': 64,
                'tcp_flags': None,
                'attack_type': 'suspicious_dns'
            })
       
        return pd.DataFrame(records)
   
    def generate_realistic_attack_scenario(self, attack_type, duration_seconds=60, packets_per_second=5):
        """Generate a realistic attack scenario with proper flow."""
        records = []
       
        # Base timestamp for the scenario
        base_timestamp = time.time()
       
        # Port scan scenario
        if attack_type == 'port_scan':
            attacker_ip = self.generate_ip(internal=False)
            target_ip = self.generate_ip(internal=True)
           
            # First phase: Initial reconnaissance (slower, random ports)
            recon_duration = duration_seconds * 0.2  # 20% of total duration
            recon_packets = int(recon_duration * packets_per_second * 0.3)  # Lower packet rate
           
            for i in range(recon_packets):
                timestamp = base_timestamp + (i * (recon_duration / recon_packets))
                port = random.randint(1, 49151)
               
                records.append({
                    'timestamp': timestamp,
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'src_port': random.randint(10000, 65535),
                    'dst_port': port,
                    'protocol': 'TCP',
                    'length': random.randint(40, 60),
                    'ttl': 64,
                    'tcp_flags': 2,  # SYN flag
                    'attack_type': 'port_scan'
                })
           
            # Second phase: Systematic port scanning (faster, sequential ports)
            main_start_time = base_timestamp + recon_duration
            main_duration = duration_seconds * 0.8
            main_packets = int(main_duration * packets_per_second)
           
            # Sequential port ranges
            port_ranges = [
                (20, 25),      # FTP, SSH, Telnet
                (80, 90),      # HTTP, common web
                (440, 450),    # HTTPS and related
                (3300, 3400),  # Common services
                (5900, 6000)   # VNC and others
            ]
           
            current_range = 0
            current_port = port_ranges[0][0]
           
            for i in range(main_packets):
                timestamp = main_start_time + (i * (main_duration / main_packets))
               
                # Move to next port
                current_port += 1
                if current_port > port_ranges[current_range][1]:
                    current_range = (current_range + 1) % len(port_ranges)
                    current_port = port_ranges[current_range][0]
               
                records.append({
                    'timestamp': timestamp,
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'src_port': random.randint(10000, 65535),
                    'dst_port': current_port,
                    'protocol': 'TCP',
                    'length': random.randint(40, 60),
                    'ttl': 64,
                    'tcp_flags': 2,  # SYN flag
                    'attack_type': 'port_scan'
                })
       
        # Brute force scenario
        elif attack_type == 'brute_force':
            attacker_ip = self.generate_ip(internal=False)
            target_ip = self.generate_ip(internal=True)
           
            # Pick service to attack
            service = random.choice(['SSH', 'FTP', 'TELNET', 'RDP'])
            port_map = {'SSH': 22, 'FTP': 21, 'TELNET': 23, 'RDP': 3389}
            target_port = port_map[service]
           
            # Connection pattern: establish, auth attempts, disconnect
            for attempt in range(int(duration_seconds * packets_per_second / 3)):
                # Each attempt has 3 packets: connection, auth, disconnect
                base_time = base_timestamp + (attempt * 3 / packets_per_second)
                src_port = random.randint(10000, 65535)
               
                # Connection packet
                records.append({
                    'timestamp': base_time,
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'src_port': src_port,
                    'dst_port': target_port,
                    'protocol': service,
                    'length': random.randint(60, 120),
                    'ttl': 64,
                    'tcp_flags': 2,  # SYN
                    'attack_type': 'brute_force'
                })
               
                # Authentication packet (larger)
                records.append({
                    'timestamp': base_time + 0.2,
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'src_port': src_port,
                    'dst_port': target_port,
                    'protocol': service,
                    'length': random.randint(200, 500),
                    'ttl': 64,
                    'tcp_flags': 16,  # ACK
                    'attack_type': 'brute_force'
                })
               
                # Disconnect packet (often after failed auth)
                records.append({
                    'timestamp': base_time + 0.5,
                    'src_ip': attacker_ip,
                    'dst_ip': target_ip,
                    'src_port': src_port,
                    'dst_port': target_port,
                    'protocol': service,
                    'length': random.randint(40, 100),
                    'ttl': 64,
                    'tcp_flags': 17,  # FIN+ACK
                    'attack_type': 'brute_force'
                })
       
        # DDoS Scenario
        elif attack_type == 'ddos':
            # Generate multiple source IPs
            num_sources = min(100, int(duration_seconds * packets_per_second / 10))
            source_ips = [self.generate_ip(internal=False) for _ in range(num_sources)]
            target_ip = self.generate_ip(internal=True)
            target_port = random.choice([80, 443, 8080, 53])
           
            # Generate traffic from each source
            for i in range(int(duration_seconds * packets_per_second)):
                timestamp = base_timestamp + (i / packets_per_second)
                src_ip = random.choice(source_ips)
               
                records.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': target_ip,
                    'src_port': random.randint(10000, 65535),
                    'dst_port': target_port,
                    'protocol': random.choice(['TCP', 'UDP']),
                    'length': random.randint(500, 1500),
                    'ttl': 64,
                    'tcp_flags': 2 if random.random() < 0.7 else 16,  # Mostly SYN
                    'attack_type': 'ddos'
                })
       
        # Add more scenarios as needed
       
        return pd.DataFrame(records) if records else None
   
    def _generate_attack_packet(self, attack_type=None):
        """Generate a single attack packet based on attack type."""
        if attack_type is None:
            # Choose attack type based on weights
            attack_types = list(self.attack_types.keys())
            attack_weights = [self.attack_types[a]['weight'] for a in attack_types]
            total_weight = sum(attack_weights)
            normalized_weights = [w/total_weight for w in attack_weights]
            attack_type = np.random.choice(attack_types, p=normalized_weights)
       
        # Start with a normal packet
        packet = self._generate_normal_packet()
       
        # Modify packet based on attack pattern
        pattern = self.attack_types[attack_type]['pattern']
       
        if pattern == 'many_ports':
            # Port scan - random high ports
            packet['dst_port'] = random.randint(1, 65535)
            packet['protocol'] = 'TCP'
            packet['length'] = random.randint(40, 100)  # Small packets
            packet['tcp_flags'] = 2  # SYN flag
           
        elif pattern == 'high_volume':
            # DDoS - large packets, same destination
            packet['length'] = random.randint(1000, self.packet_size_max)  # Large packets
            packet['dst_ip'] = self.generate_ip(internal=True)  # Target server
            packet['protocol'] = random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS'])
            packet['tcp_flags'] = random.choice([2, 18, 16])  # SYN, SYN-ACK, ACK
           
        elif pattern == 'repeated_auth':
            # Brute force - repeated SSH/login connections
            packet['protocol'] = random.choice(['SSH', 'TELNET', 'FTP', 'SMB'])
            if packet['protocol'] == 'SSH':
                packet['dst_port'] = 22
            elif packet['protocol'] == 'TELNET':
                packet['dst_port'] = 23
            elif packet['protocol'] == 'FTP':
                packet['dst_port'] = 21
            elif packet['protocol'] == 'SMB':
                packet['dst_port'] = 445
            packet['dst_ip'] = self.generate_ip(internal=True)  # Auth server
            packet['tcp_flags'] = 16  # ACK flag
           
        elif pattern == 'large_outbound':
            # Data exfiltration - large outbound packets
            packet['src_ip'] = self.generate_ip(internal=True)
            packet['dst_ip'] = self.generate_ip(internal=False)
            packet['length'] = random.randint(1200, self.packet_size_max)  # Large packets
            packet['dst_port'] = random.choice([6667, 4444, 8443, 8080, 9001])
            packet['tcp_flags'] = 16  # ACK flag
           
        elif pattern == 'unusual_port':
            # Malware communication - unusual ports
            packet['dst_port'] = random.choice([6666, 4444, 31337, 12345, 54321])
            packet['dst_ip'] = self.generate_ip(internal=False)
            packet['src_ip'] = self.generate_ip(internal=True)
            packet['tcp_flags'] = 16  # ACK flag
           
        elif pattern == 'dns_tunnel':
            # Suspicious DNS - larger DNS packets or high frequency
            packet['protocol'] = 'DNS'
            packet['dst_port'] = 53
            packet['dst_ip'] = random.choice(["8.8.8.8", "1.1.1.1", self.generate_ip(internal=False)])
            packet['length'] = random.randint(300, 500)  # Larger packets for tunneling
            packet['tcp_flags'] = None
       
        # Set the attack type
        packet['attack_type'] = attack_type
       
        return packet
   
    def generate_mixed_traffic(self, normal_ratio=0.8, num_records=1000, timeframe=3600):
        """Generate a mix of normal and attack traffic."""
        # Determine how many normal vs attack records to generate
        normal_count = int(num_records * normal_ratio)
        attack_count = num_records - normal_count
       
        # Generate normal traffic
        normal_data = []
        for _ in range(normal_count):
            normal_data.append(self._generate_normal_packet(timeframe))
        normal_df = pd.DataFrame(normal_data)
       
        # Generate attack traffic if needed
        if attack_count > 0:
            # Choose which attack types to include
            attack_weights = {k: v['frequency'] for k, v in self.attack_types.items()}
            total_weight = sum(attack_weights.values())
            normalized_weights = {k: v/total_weight for k, v in attack_weights.items()}
           
            attack_counts = {}
            remaining = attack_count
           
            # Distribute attack count among attack types
            for attack_type in list(normalized_weights.keys())[:-1]:
                attack_counts[attack_type] = int(attack_count * normalized_weights[attack_type])
                remaining -= attack_counts[attack_type]
           
            # Assign remaining to the last attack type
            last_attack = list(normalized_weights.keys())[-1]
            attack_counts[last_attack] = remaining
           
            # Generate each attack type
            attack_dataframes = []
            for attack_type, count in attack_counts.items():
                if count <= 0:
                    continue
                   
                if attack_type == 'port_scan':
                    attack_df = self._generate_port_scan(count)
                elif attack_type == 'ddos':
                    attack_df = self._generate_ddos_attack(count)
                elif attack_type == 'data_exfiltration':
                    attack_df = self._generate_data_exfiltration(count)
                elif attack_type == 'brute_force':
                    attack_df = self._generate_brute_force(count)
                elif attack_type == 'malware_c2':
                    attack_df = self._generate_malware_c2(count)
                elif attack_type == 'suspicious_dns':
                    attack_df = self._generate_suspicious_dns(count)
               
                attack_dataframes.append(attack_df)
           
            # Combine normal and attack traffic
            if attack_dataframes:
                all_attacks_df = pd.concat(attack_dataframes)
                traffic_df = pd.concat([normal_df, all_attacks_df])
            else:
                traffic_df = normal_df
           
            # Sort by timestamp
            traffic_df = traffic_df.sort_values('timestamp')
        else:
            traffic_df = normal_df
       
        return traffic_df
   
    def generate_batch(self, batch_size=100, include_attacks=True, attack_ratio=0.2):
        """Generate a batch of simulated network traffic data (alternative method)."""
        # This is provided for compatibility with the second implementation
        if include_attacks:
            return self.generate_mixed_traffic(normal_ratio=1-attack_ratio, num_records=batch_size)
        else:
            return self._generate_normal_traffic(num_records=batch_size)
   
    def _generate_and_save_batch(self, batch_id):
        """Generate and save a batch of traffic."""
        try:
            # Generate traffic
            self.logger.info(f"Generating batch {batch_id}")
            df = self.generate_mixed_traffic(normal_ratio=0.8, num_records=random.randint(50, 200))
           
            # Save to CSV
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = os.path.join(self.output_dir, f"{timestamp}_batch_{batch_id}_traffic.csv")
            df.to_csv(output_file, index=False)
           
            self.logger.info(f"Saved batch {batch_id} with {len(df)} records to {output_file}")
            return output_file
        except Exception as e:
            self.logger.error(f"Error generating batch {batch_id}: {str(e)}")
            return None
   
    def _simulate_continuous(self, interval=10):
        """Continuously generate traffic in a background thread."""
        batch_id = 1
       
        while self.running:
            self._generate_and_save_batch(batch_id)
            batch_id += 1
            time.sleep(interval)
   
    def start_simulation(self, interval=10):
        """Start continuous traffic simulation."""
        if self.thread and self.thread.is_alive():
            self.logger.warning("Simulation already running")
            return False
       
        self.running = True
        self.thread = threading.Thread(target=self._simulate_continuous, args=(interval,))
        self.thread.daemon = True
        self.thread.start()
       
        self.logger.info(f"Started continuous traffic simulation with {interval}s interval")
        return True
   
    def stop_simulation(self):
        """Stop continuous traffic simulation."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5.0)
            self.logger.info("Stopped traffic simulation")
        return True
   
    def generate_single_batch(self, num_records=1000):
        """Generate a single batch of traffic and return the dataframe."""
        return self.generate_mixed_traffic(normal_ratio=0.8, num_records=num_records)

if __name__ == "__main__":
    # Example usage
    simulator = TrafficSimulator()
   
    # Generate a single batch
    df = simulator.generate_single_batch(500)
    print(f"Generated {len(df)} records")
    print(df.head())
   
    # Count attack types
    if 'attack_type' in df.columns:
        print("\nAttack distribution:")
        print(df['attack_type'].value_counts())
       
    # Example of continuous simulation
    # simulator.start_simulation(interval=30)
    # try:
    #     # Run for 5 minutes then stop
    #     time.sleep(300)
    # finally:
    #     simulator.stop_simulation()
   
    # Example of realistic attack scenario
    print("\nGenerating realistic port scan scenario:")
    port_scan_df = simulator.generate_realistic_attack_scenario('port_scan', duration_seconds=30)
    if port_scan_df is not None:
        print(f"Generated {len(port_scan_df)} port scan packets")
        print(port_scan_df.head())
   
    print("\nGenerating realistic brute force scenario:")
    brute_force_df = simulator.generate_realistic_attack_scenario('brute_force', duration_seconds=20)
    if brute_force_df is not None:
        print(f"Generated {len(brute_force_df)} brute force packets")
        print(brute_force_df.head())