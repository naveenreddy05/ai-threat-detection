import os
import sys
import time
import logging
import argparse
from datetime import datetime
import pyshark
import pandas as pd
import numpy as np
from scapy.all import sniff, wrpcap

class NetworkCapture:
    """
    Class for capturing network traffic and storing it in raw format.
    """
    def __init__(self, interface=None, pcap_file=None, output_dir="../data/raw"):
        """
        Initialize NetworkCapture with either a network interface or a pcap file.
        
        Args:
            interface (str): Network interface to capture from (e.g., 'eth0')
            pcap_file (str): Path to pcap file to read from
            output_dir (str): Directory to save captured data
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.packets = []
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def capture_live(self, duration=60, packet_count=1000, output_file=None):
        """
        Capture live network traffic.
        
        Args:
            duration (int): Duration in seconds to capture
            packet_count (int): Maximum number of packets to capture
            output_file (str): Filename to save capture (default: timestamp-based)
        
        Returns:
            str: Path to saved pcap file
        """
        if not self.interface:
            self.logger.error("No interface specified for live capture")
            return None
            
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_capture.pcap"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        self.logger.info(f"Starting packet capture on interface {self.interface}")
        try:
            # Using scapy for packet capture
            packets = sniff(iface=self.interface, count=packet_count, timeout=duration)
            wrpcap(output_path, packets)
            self.logger.info(f"Captured {len(packets)} packets, saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")
            return None
    
    def read_pcap(self, pcap_file=None):
        """
        Read packets from a pcap file.
        
        Args:
            pcap_file (str): Path to pcap file (uses self.pcap_file if None)
            
        Returns:
            list: Captured packets
        """
        file_path = pcap_file or self.pcap_file
        
        if not file_path:
            self.logger.error("No pcap file specified")
            return []
            
        if not os.path.exists(file_path):
            self.logger.error(f"PCAP file not found: {file_path}")
            return []
            
        self.logger.info(f"Reading packets from {file_path}")
        try:
            # Using pyshark to parse pcap file
            cap = pyshark.FileCapture(file_path)
            packets = [packet for packet in cap]
            self.logger.info(f"Read {len(packets)} packets from {file_path}")
            return packets
        except Exception as e:
            self.logger.error(f"Error reading pcap file: {str(e)}")
            return []
    
    def extract_basic_features(self, packets=None):
        """
        Extract basic features from packets.
        
        Args:
            packets (list): List of packets (uses self.packets if None)
            
        Returns:
            pandas.DataFrame: DataFrame with basic packet features
        """
        if packets is None:
            packets = self.packets
            
        if not packets:
            self.logger.warning("No packets to extract features from")
            return pd.DataFrame()
            
        self.logger.info("Extracting basic features from packets")
# Initialize lists to store features
        data = []
        
        # Process each packet
        for i, packet in enumerate(packets):
            try:
                # Extract basic features
                packet_dict = {
                    'timestamp': float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else time.time(),
                    'length': int(packet.length) if hasattr(packet, 'length') else 0,
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'UNKNOWN'
                }
                
                # Add IP layer features if present
                if hasattr(packet, 'ip'):
                    packet_dict['src_ip'] = packet.ip.src
                    packet_dict['dst_ip'] = packet.ip.dst
                    packet_dict['ttl'] = int(packet.ip.ttl)
                
                # Add transport layer features if present
                if hasattr(packet, 'tcp'):
                    packet_dict['src_port'] = int(packet.tcp.srcport)
                    packet_dict['dst_port'] = int(packet.tcp.dstport)
                    packet_dict['tcp_flags'] = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None
                elif hasattr(packet, 'udp'):
                    packet_dict['src_port'] = int(packet.udp.srcport)
                    packet_dict['dst_port'] = int(packet.udp.dstport)
                    packet_dict['tcp_flags'] = None
                
                data.append(packet_dict)
            except Exception as e:
                self.logger.warning(f"Error processing packet {i}: {str(e)}")
                continue
        
        # Create DataFrame from collected data
        df = pd.DataFrame(data)
        self.logger.info(f"Extracted features from {len(df)} packets")
        
        return df
    
    def save_features(self, df, output_file=None):
        """
        Save extracted features to CSV file.
        
        Args:
            df (pandas.DataFrame): DataFrame with packet features
            output_file (str): Filename to save features (default: timestamp-based)
            
        Returns:
            str: Path to saved CSV file
        """
        if df.empty:
            self.logger.warning("No features to save")
            return None
            
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_features.csv"
        
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            df.to_csv(output_path, index=False)
            self.logger.info(f"Saved {len(df)} packet features to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error saving features: {str(e)}")
            return None
def main():
    """
    Main function to run the network capture module.
    """
    parser = argparse.ArgumentParser(description="Network Traffic Capture Tool")
    parser.add_argument("--interface", "-i", help="Network interface to capture from")
    parser.add_argument("--pcap", "-p", help="PCAP file to read from")
    parser.add_argument("--output", "-o", help="Output directory", default="../data/raw")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Capture duration in seconds")
    parser.add_argument("--count", "-c", type=int, default=1000, help="Maximum number of packets to capture")
    
    args = parser.parse_args()
    
    if not args.interface and not args.pcap:
        print("Error: Either --interface or --pcap must be specified")
        parser.print_help()
        sys.exit(1)
    
    capture = NetworkCapture(interface=args.interface, pcap_file=args.pcap, output_dir=args.output)
    
    if args.interface:
        pcap_path = capture.capture_live(duration=args.duration, packet_count=args.count)
        if pcap_path:
            packets = capture.read_pcap(pcap_path)
        else:
            sys.exit(1)
    else:
        packets = capture.read_pcap()
    
    if packets:
        df = capture.extract_basic_features(packets)
        capture.save_features(df)

if __name__== "__main__":
    main()
