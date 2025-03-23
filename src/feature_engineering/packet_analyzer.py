import os
import sys
import logging
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
import pyshark
from scapy.all import rdpcap
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

class PacketAnalyzer:
    """
    Class for analyzing network packets and generating insights.
    """
    def __init__(self, input_dir="../data/raw", output_dir="../data/results"):
        """
        Initialize PacketAnalyzer.
       
        Args:
            input_dir (str): Directory containing packet data
            output_dir (str): Directory to save analysis results
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
       
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
           
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
   
    def load_pcap(self, pcap_file):
        """
        Load packets from a pcap file.
       
        Args:
            pcap_file (str): Path to pcap file
           
        Returns:
            list: Captured packets
        """
        if not os.path.exists(pcap_file):
            self.logger.error(f"PCAP file not found: {pcap_file}")
            return []
           
        self.logger.info(f"Loading packets from {pcap_file}")
        try:
            # Using pyshark to parse pcap file for analysis
            cap = pyshark.FileCapture(pcap_file)
            packets = [packet for packet in cap]
            self.logger.info(f"Loaded {len(packets)} packets")
            return packets
        except Exception as e:
            self.logger.error(f"Error loading pcap file: {str(e)}")
            return []
   
    def load_packet_features(self, feature_file):
        """
        Load packet features from a CSV file.
       
        Args:
            feature_file (str): Path to feature CSV file
           
        Returns:
            pandas.DataFrame: Packet features
        """
        if not os.path.exists(feature_file):
            self.logger.error(f"Feature file not found: {feature_file}")
            return pd.DataFrame()
           
        self.logger.info(f"Loading packet features from {feature_file}")
        try:
            df = pd.read_csv(feature_file)
            self.logger.info(f"Loaded {len(df)} packet records with {df.shape[1]} features")
            return df
        except Exception as e:
            self.logger.error(f"Error loading feature file: {str(e)}")
            return pd.DataFrame()
   
    def analyze_protocols(self, packets):
        """
        Analyze protocol distribution.
       
        Args:
            packets (list): List of packets
           
        Returns:
            dict: Protocol analysis results
        """
        self.logger.info("Analyzing protocol distribution")
       
        # Count protocols at different layers
        layer_counters = {
            'eth_types': Counter(),
            'ip_protos': Counter(),
            'transport_protos': Counter(),
            'app_protos': Counter()
        }
       
        # Analyze each packet
        for packet in packets:
            # Ethernet layer
            if hasattr(packet, 'eth'):
                eth_type = packet.eth.type if hasattr(packet.eth, 'type') else 'unknown'
                layer_counters['eth_types'][eth_type] += 1
           
            # IP layer
            if hasattr(packet, 'ip'):
                ip_proto = packet.ip.proto if hasattr(packet.ip, 'proto') else 'unknown'
                layer_counters['ip_protos'][ip_proto] += 1
           
            # Transport layer
            if hasattr(packet, 'tcp'):
                layer_counters['transport_protos']['TCP'] += 1
            elif hasattr(packet, 'udp'):
                layer_counters['transport_protos']['UDP'] += 1
           
            # Application layer (highest layer)
            highest_layer = packet.highest_layer if hasattr(packet, 'highest_layer') else 'unknown'
            layer_counters['app_protos'][highest_layer] += 1
       
        # Prepare results
        results = {
            'packet_count': len(packets),
            'layer_distribution': {
                'ethernet': dict(layer_counters['eth_types'].most_common()),
                'ip': dict(layer_counters['ip_protos'].most_common()),
                'transport': dict(layer_counters['transport_protos'].most_common()),
                'application': dict(layer_counters['app_protos'].most_common())
            }
        }
       
        return results
   
    def analyze_endpoints(self, df):
        """
        Analyze communication patterns between endpoints.
       
        Args:
            df (pandas.DataFrame): Packet features DataFrame
           
        Returns:
            dict: Endpoint analysis results
        """
        if df.empty or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            self.logger.warning(" 
