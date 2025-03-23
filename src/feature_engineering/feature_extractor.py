import os
import sys
import logging
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
import joblib
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
import networkx as nx

class FeatureExtractor:
    """
    Class for advanced feature extraction from network traffic data.
    """
    def __init__(self, input_dir="../data/processed", output_dir="../data/processed"):
        """
        Initialize FeatureExtractor.
       
        Args:
            input_dir (str): Directory containing processed data
            output_dir (str): Directory to save extracted features
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
   
    def load_data(self, enriched_file=None, flow_file=None):
        """
        Load processed data.
       
        Args:
            enriched_file (str): Path to enriched data file
            flow_file (str): Path to flow features file
           
        Returns:
            tuple: (Enriched DataFrame, Flow DataFrame)
        """
        enriched_df = pd.DataFrame()
        flow_df = pd.DataFrame()
       
        # Load enriched data
        if not enriched_file:
            # Find most recent enriched data file
            enriched_files = [f for f in os.listdir(self.input_dir) if f.endswith('_enriched.csv')]
            if enriched_files:
                enriched_files.sort(reverse=True)
                enriched_file = os.path.join(self.input_dir, enriched_files[0])
       
        if enriched_file and os.path.exists(enriched_file):
            try:
                self.logger.info(f"Loading enriched data from {enriched_file}")
                enriched_df = pd.read_csv(enriched_file)
                self.logger.info(f"Loaded {len(enriched_df)} records")
            except Exception as e:
                self.logger.error(f"Error loading enriched data: {str(e)}")
       
        # Load flow data
        if not flow_file:
            # Find most recent flow data file
            flow_files = [f for f in os.listdir(self.input_dir) if f.endswith('_flows.csv')]
            if flow_files:
                flow_files.sort(reverse=True)
                flow_file = os.path.join(self.input_dir, flow_files[0])
       
        if flow_file and os.path.exists(flow_file):
            try:
                self.logger.info(f"Loading flow data from {flow_file}")
                flow_df = pd.read_csv(flow_file)
                self.logger.info(f"Loaded {len(flow_df)} flow records")
            except Exception as e:
                self.logger.error(f"Error loading flow data: {str(e)}")
       
        return enriched_df, flow_df
   
    def extract_protocol_distribution(self, df):
        """
        Extract protocol distribution features.
       
        Args:
            df (pandas.DataFrame): Input data with protocol information
           
        Returns:
            pandas.DataFrame: Protocol distribution features
        """
        if 'protocol' not in df.columns or 'flow' not in df.columns or 'time_window' not in df.columns:
            self.logger.warning("Required columns missing for protocol distribution extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting protocol distribution features")
       
        # Group by flow and time window
        protocol_counts = df.groupby(['flow', 'time_window', 'protocol']).size().unstack(fill_value=0)
       
        # Calculate protocol ratios
        protocol_counts_sum = protocol_counts.sum(axis=1).to_frame('total')
        protocol_ratios = protocol_counts.div(protocol_counts_sum['total'], axis=0)
       
        # Rename columns to indicate they are ratios
        protocol_ratios.columns = [f'ratio_{col}' for col in protocol_ratios.columns]
       
        # Combine counts and ratios
        result = pd.concat([protocol_counts, protocol_ratios], axis=1)
       
        # Reset index to get flow and time_window as columns
        result = result.reset_index()
       
        return result
   
    def extract_port_features(self, df):
        """
        Extract port-related features.
       
        Args:
            df (pandas.DataFrame): Input data with port information
           
        Returns:
            pandas.DataFrame: Port-related features
        """
        if 'src_port' not in df.columns or 'dst_port' not in df.columns:
            self.logger.warning("Port columns missing for port feature extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting port-related features")
       
        # Create a copy of the dataframe
        result = df.copy()
       
        # Well-known ports
        well_known_ports = [20, 21, 22, 23, 25, 53, 80, 123, 143, 161, 443, 445, 993, 995, 3306, 3389, 8080]
       
        # Add features for well-known ports
        result['src_port_well_known'] = result['src_port'].isin(well_known_ports)
        result['dst_port_well_known'] = result['dst_port'].isin(well_known_ports)
       
        # Check if ports are in range of registered ports (1024-49151)
        result['src_port_registered'] = (result['src_port'] >= 1024) & (result['src_port'] <= 49151)
        result['dst_port_registered'] = (result['dst_port'] >= 1024) & (result['dst_port'] <= 49151)
       
        # Check if ports are in range of dynamic/private ports (49152-65535)
        result['src_port_dynamic'] = result['src_port'] >= 49152
        result['dst_port_dynamic'] = result['dst_port'] >= 49152
       
        # Calculate port numbers entropy if grouped by flow and time window
        if 'flow' in result.columns and 'time_window' in result.columns:
            port_entropy = result.groupby(['flow', 'time_window']).apply(
                lambda x: self._calculate_entropy(x['src_port']) + self._calculate_entropy(x['dst_port'])
            ).reset_index(name='port_entropy')
           
            # Merge back to result
            result = result.merge(port_entropy, on=['flow', 'time_window'], how='left')
       
        return result
   
    def _calculate_entropy(self, values):
        """
        Calculate Shannon entropy of a series of values.
       
        Args:
            values (pandas.Series): Series of values
           
        Returns:
            float: Shannon entropy
        """
        # Count frequency of each value
        value_counts = values.value_counts(normalize=True)
       
        # Calculate entropy
        entropy = -np.sum(value_counts * np.log2(value_counts))
       
        return entropy
   
    def extract_network_graph_features(self, df):
        """
        Extract network graph-based features.
       
        Args:
            df (pandas.DataFrame): Input data with IP addresses
           
        Returns:
            pandas.DataFrame: Graph-based features
        """
        if 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            self.logger.warning("IP address columns missing for graph feature extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting network graph features")
       
        # Create network graph
        G = nx.DiGraph()
       
        # Add edges from source to destination IP
        for _, row in df.iterrows():
            src = row['src_ip']
            dst = row['dst_ip']
           
            # Add edge with weight (count if edge already exists)
            if G.has_edge(src, dst):
                G[src][dst]['weight'] += 1
            else:
                G.add_edge(src, dst, weight=1)
       
        # Calculate node-level metrics
        node_degrees = dict(G.degree())
        node_in_degrees = dict(G.in_degree())
        node_out_degrees = dict(G.out_degree())
       
        # Calculate centrality metrics
        try:
            betweenness_centrality = nx.betweenness_centrality(G, weight='weight')
            closeness_centrality = nx.closeness_centrality(G)
            eigenvector_centrality = nx.eigenvector_centrality(G, weight='weight', max_iter=100)
        except Exception as e:
            self.logger.warning(f"Error calculating some centrality metrics: {str(e)}")
            betweenness_centrality = {}
            closeness_centrality = {}
            eigenvector_centrality = {}
       
        # Create IP-level features DataFrame
        ip_features = pd.DataFrame()
       
        # Add all unique IPs (both source and destination)
        all_ips = set(df['src_ip']).union(set(df['dst_ip']))
        ip_features['ip'] = list(all_ips)
       
        # Add graph metrics
        ip_features['degree'] = ip_features['ip'].map(lambda x: node_degrees.get(x, 0))
        ip_features['in_degree'] = ip_features['ip'].map(lambda x: node_in_degrees.get(x, 0))
        ip_features['out_degree'] = ip_features['ip'].map(lambda x: node_out_degrees.get(x, 0))
        ip_features['betweenness'] = ip_features['ip'].map(lambda x: betweenness_centrality.get(x, 0))
        ip_features['closeness'] = ip_features['ip'].map(lambda x: closeness_centrality.get(x, 0))
        ip_features['eigenvector'] = ip_features['ip'].map(lambda x: eigenvector_centrality.get(x, 0))
       
        # Calculate additional metrics
        ip_features['in_out_ratio'] = ip_features.apply(
            lambda row: row['in_degree'] / row['out_degree'] if row['out_degree'] > 0 else 0,
            axis=1
        )
       
        # Join back to original data for source IP
        src_features = ip_features.copy()
        src_features.columns = ['src_ip' if col == 'ip' else f'src_{col}' for col in src_features.columns]
       
        # Join back to original data for destination IP
        dst_features = ip_features.copy()
        dst_features.columns = ['dst_ip' if col == 'ip' else f'dst_{col}' for col in dst_features.columns]
       
        # Merge features back to the original data
        result = df.merge(src_features, on='src_ip', how='left')
        result = result.merge(dst_features, on='dst_ip', how='left')
       
        return result
   
    def extract_temporal_features(self, df):
        """
        Extract temporal pattern features.
       
        Args:
            df (pandas.DataFrame): Input data with timestamp information
           
        Returns:
            pandas.DataFrame: Temporal features
        """
        if 'timestamp' not in df.columns:
            self.logger.warning("Timestamp column missing for temporal feature extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting temporal pattern features")
       
        # Create a copy of the dataframe
        result = df.copy()
       
        # Convert timestamp to datetime if it's not already
        if pd.api.types.is_numeric_dtype(result['timestamp']):
            result['datetime'] = pd.to_datetime(result['timestamp'], unit='s')
        else:
            result['datetime'] = pd.to_datetime(result['timestamp'])
       
        # Extract time components
        result['hour'] = result['datetime'].dt.hour
        result['minute'] = result['datetime'].dt.minute
        result['day_of_week'] = result['datetime'].dt.dayofweek
        result['is_weekend'] = result['day_of_week'] >= 5
       
        # Business hours flag (9 AM to 5 PM, Monday to Friday)
        result['is_business_hours'] = ((result['hour'] >= 9) &
                                       (result['hour'] < 17) &
                                       (result['day_of_week'] < 5))
       
        # Calculate inter-arrival times if data has flow information
        if 'flow' in result.columns:
            # Sort by flow and timestamp
            result = result.sort_values(['flow', 'timestamp'])
           
            # Calculate time difference between consecutive packets in the same flow
            result['prev_timestamp'] = result.groupby('flow')['timestamp'].shift(1)
            result['inter_arrival_time'] = result['timestamp'] - result['prev_timestamp']
           
            # Replace NaN values (first packet in each flow) with 0
            result['inter_arrival_time'] = result['inter_arrival_time'].fillna(0)
           
            # Calculate statistics on inter-arrival times by flow
            iat_stats = result.groupby('flow')['inter_arrival_time'].agg([
                ('iat_mean', 'mean'),
                ('iat_std', 'std'),
                ('iat_min', 'min'),
                ('iat_max', 'max')
            ]).reset_index()
           
            # Merge statistics back to the result
            result = result.merge(iat_stats, on='flow', how='left')
           
            # Clean up temporary columns
            result = result.drop(['prev_timestamp'], axis=1)
       
        # Calculate packet burst features
        if 'flow' in result.columns and 'time_window' in result.columns:
            # Count packets per flow per second
            packet_counts = result.groupby(['flow', result['timestamp'].astype(int)])['length'].count().reset_index()
            packet_counts.columns = ['flow', 'second', 'packets_per_second']
           
            # Calculate statistics on packets per second by flow
            pps_stats = packet_counts.groupby('flow')['packets_per_second'].agg([
                ('pps_mean', 'mean'),
                ('pps_std', 'std'),
                ('pps_min', 'min'),
                ('pps_max', 'max'),
                ('pps_sum', 'sum')
            ]).reset_index()
           
            # Merge statistics back to the result
            result = result.merge(pps_stats, on='flow', how='left')
       
        # Drop datetime column as we've extracted what we need
        result = result.drop(['datetime'], axis=1)
       
        return result
   
    def extract_packet_pattern_features(self, df):
        """
        Extract packet pattern features.
       
        Args:
            df (pandas.DataFrame): Input data with packet information
           
        Returns:
            pandas.DataFrame: Packet pattern features
        """
        if 'length' not in df.columns:
            self.logger.warning("Length column missing for packet pattern feature extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting packet pattern features")
       
        # Create a copy of the dataframe
        result = df.copy()
       
        # Calculate packet size categories
        result['packet_size_tiny'] = result['length'] < 64
        result['packet_size_small'] = (result['length'] >= 64) & (result['length'] < 256)
        result['packet_size_medium'] = (result['length'] >= 256) & (result['length'] < 1024)
        result['packet_size_large'] = (result['length'] >= 1024) & (result['length'] < 1500)
        result['packet_size_jumbo'] = result['length'] >= 1500
       
        # If data has flow information, calculate additional statistics
        if 'flow' in result.columns and 'time_window' in result.columns:
            # Group by flow and time window
            flow_stats = result.groupby(['flow', 'time_window']).agg({
                'length': ['mean', 'std', 'min', 'max', 'sum', 'count'],
                'packet_size_tiny': 'sum',
                'packet_size_small': 'sum',
                'packet_size_medium': 'sum',
                'packet_size_large': 'sum',
                'packet_size_jumbo': 'sum'
            })
           
            # Flatten column names
            flow_stats.columns = ['_'.join(col).strip() for col in flow_stats.columns.values]
            flow_stats = flow_stats.reset_index()
           
            # Calculate size distribution ratios
            total_packets = flow_stats['packet_size_tiny_sum'] + flow_stats['packet_size_small_sum'] + \
                            flow_stats['packet_size_medium_sum'] + flow_stats['packet_size_large_sum'] + \
                            flow_stats['packet_size_jumbo_sum']
           
            flow_stats['ratio_tiny'] = flow_stats['packet_size_tiny_sum'] / total_packets
            flow_stats['ratio_small'] = flow_stats['packet_size_small_sum'] / total_packets
            flow_stats['ratio_medium'] = flow_stats['packet_size_medium_sum'] / total_packets
            flow_stats['ratio_large'] = flow_stats['packet_size_large_sum'] / total_packets
            flow_stats['ratio_jumbo'] = flow_stats['packet_size_jumbo_sum'] / total_packets
           
            # Replace NaN values with 0
            flow_stats = flow_stats.fillna(0)
           
            return flow_stats
       
        return result
   
    def reduce_features(self, df, n_features=None, use_pca=False):
        """
        Reduce feature dimensionality.
       
        Args:
            df (pandas.DataFrame): Input features
            n_features (int): Number of features to select
            use_pca (bool): Whether to use PCA or SelectKBest
           
        Returns:
            tuple: (Reduced features DataFrame, Feature selector)
        """
        # Drop non-feature columns
        feature_cols = df.columns.difference(['flow', 'time_window', 'src_ip', 'dst_ip', 'timestamp'])
        X = df[feature_cols]
       
        # Handle categorical features
        X = pd.get_dummies(X)
       
        # Fill missing values
        X = X.fillna(0)
       
        # Default to 1/3 of features if n_features not specified
        if n_features is None:
            n_features = max(1, X.shape[1] // 3)
       
        self.logger.info(f"Reducing features from {X.shape[1]} to {n_features}")
       
        feature_reducer = None
        X_reduced = X
       
        try:
            if use_pca:
                # Apply PCA
                feature_reducer = PCA(n_components=n_features)
                X_reduced_np = feature_reducer.fit_transform(X)
               
                # Convert to DataFrame with feature names
                X_reduced = pd.DataFrame(
                    X_reduced_np,
                    columns=[f'PC{i+1}' for i in range(n_features)]
                )
               
                self.logger.info(f"PCA explained variance: {feature_reducer.explained_variance_ratio_.sum():.2f}")
            else:
                # Apply SelectKBest
                feature_reducer = SelectKBest(f_classif, k=n_features)
                X_reduced_np = feature_reducer.fit_transform(X, np.zeros(X.shape[0]))  # Dummy y values
               
                # Get selected feature names
                selected_features = X.columns[feature_reducer.get_support()]
               
                # Convert to DataFrame with feature names
                X_reduced = pd.DataFrame(X_reduced_np, columns=selected_features)
               
                self.logger.info(f"Selected features: {', '.join(selected_features[:5])}...")
           
            return X_reduced, feature_reducer
           
        except Exception as e:
            self.logger.error(f"Error reducing features: {str(e)}")
            return X, None
   
    def extract_features(self, enriched_df, flow_df=None):
        """
        Extract all features from the data.
       
        Args:
            enriched_df (pandas.DataFrame): Enriched packet data
            flow_df (pandas.DataFrame): Flow-based data
           
        Returns:
            tuple: (All features, Feature extractor)
        """
        features_list = []
       
        # Extract features from packet data if available
        if not enriched_df.empty:
            self.logger.info("Extracting features from packet data")
           
            # Extract port features
            port_features = self.extract_port_features(enriched_df)
           
            # Extract temporal features
            temporal_features = self.extract_temporal_features(enriched_df)
           
            # Extract network graph features if source and destination IPs are available
            if 'src_ip' in enriched_df.columns and 'dst_ip' in enriched_df.columns:
                graph_features = self.extract_network_graph_features(enriched_df)
                features_list.append(graph_features)
       
        # Extract features from flow data if available
        if flow_df is not None and not flow_df.empty:
            self.logger.info("Extracting features from flow data")
           
            # Extract packet pattern features
            pattern_features = self.extract_packet_pattern_features(enriched_df)
           
            if not pattern_features.empty:
                features_list.append(pattern_features)
       
        # Combine all features
        if features_list:
            # Determine common join columns based on available data
            if 'flow' in features_list[0].columns and 'time_window' in features_list[0].columns:
                join_cols = ['flow', 'time_window']
            elif 'flow' in features_list[0].columns:
                join_cols = ['flow']
            else:
                # If no common join columns, return the first feature set
                return features_list[0], None
           
            # Start with the first feature set
            all_features = features_list[0]
           
            # Join with each additional feature set
            for features in features_list[1:]:
                if set(join_cols).issubset(features.columns):
                    all_features = all_features.merge(features, on=join_cols, how='outer')
           
            # Fill missing values
            all_features = all_features.fillna(0)
           
            return all_features, None
        else:
            self.logger.warning("No features were extracted")
            return pd.DataFrame(), None
   
    def save_features(self, features_df, feature_reducer=None, output_file=None):
        """
        Save extracted features.
       
        Args:
            features_df (pandas.DataFrame): Extracted features
            feature_reducer: Feature reduction model (optional)
            output_file (str): Filename prefix for output files (default: timestamp-based)
           
        Returns:
            dict: Paths to saved files
        """
        if features_df.empty:
            self.logger.warning("No features to save")
            return {}
       
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_features"
       
        result = {}
       
        try:
            # Save features
            features_path = os.path.join(self.output_dir, f"{output_file}_extracted.csv")
            features_df.to_csv(features_path, index=False)
            result['features'] = features_path
            self.logger.info(f"Saved extracted features to {features_path}")
           
            # Save feature reducer if available
            if feature_reducer is not None:
                reducer_path = os.path.join(self.output_dir, f"{output_file}_reducer.joblib")
                joblib.dump(feature_reducer, reducer_path)
                result['reducer'] = reducer_path
                self.logger.info(f"Saved feature reducer to {reducer_path}")
           
            return result
           
        except Exception as e:
            self.logger.error(f"Error saving features: {str(e)}")
            return result

# Path: src/feature_engineering/feature_extractor.py
# Continue from where it was left off

        # Extract node-level features
        node_features = pd.DataFrame({
            'ip': list(G.nodes()),
            'out_degree': [G.out_degree(n) for n in G.nodes()],
            'in_degree': [G.in_degree(n) for n in G.nodes()],
            'total_degree': [G.degree(n) for n in G.nodes()],
            'out_to_in_ratio': [G.out_degree(n) / max(G.in_degree(n), 1) for n in G.nodes()],
            'betweenness': list(nx.betweenness_centrality(G).values()),
            'clustering': list(nx.clustering(G.to_undirected()).values())
        })
       
        return node_features
   
    def extract_temporal_features(self, df):
        """
        Extract temporal features from traffic.
       
        Args:
            df (pandas.DataFrame): Input data with timestamp information
           
        Returns:
            pandas.DataFrame: Temporal features
        """
        if 'timestamp' not in df.columns:
            self.logger.warning("Timestamp column missing for temporal feature extraction")
            return pd.DataFrame()
       
        self.logger.info("Extracting temporal features")
       
        # Create a copy of the dataframe
        result = df.copy()
       
        # Convert timestamp to datetime if needed
        if pd.api.types.is_numeric_dtype(result['timestamp']):
            result['datetime'] = pd.to_datetime(result['timestamp'], unit='s')
        else:
            result['datetime'] = pd.to_datetime(result['timestamp'])
       
        # Extract time-based features
        result['hour'] = result['datetime'].dt.hour
        result['minute'] = result['datetime'].dt.minute
        result['day_of_week'] = result['datetime'].dt.dayofweek
        result['is_weekend'] = result['day_of_week'].isin([5, 6])
        result['is_night'] = (result['hour'] >= 22) | (result['hour'] <= 5)
        result['is_business_hours'] = (result['hour'] >= 9) & (result['hour'] <= 17) & (~result['is_weekend'])
       
        # Group by source IP and calculate packet inter-arrival times
        if 'src_ip' in result.columns:
            result = result.sort_values(['src_ip', 'timestamp'])
            result['prev_timestamp'] = result.groupby('src_ip')['timestamp'].shift(1)
            result['inter_arrival_time'] = result['timestamp'] - result['prev_timestamp']
           
            # Calculate statistics of inter-arrival times for each source IP
            inter_arrival_stats = result.groupby('src_ip')['inter_arrival_time'].agg([
                ('mean_inter_arrival', 'mean'),
                ('std_inter_arrival', 'std'),
                ('min_inter_arrival', 'min'),
                ('max_inter_arrival', 'max')
            ]).reset_index()
           
            # Merge back to result
            result = result.merge(inter_arrival_stats, on='src_ip', how='left')
       
        # Clean up temporary columns
        result = result.drop(['datetime', 'prev_timestamp'], axis=1, errors='ignore')
       
        return result
   
    def extract_behavioral_features(self, df, flow_df=None):
        """
        Extract behavioral features that might indicate malicious activity.
       
        Args:
            df (pandas.DataFrame): Input data
            flow_df (pandas.DataFrame): Flow features data if available
           
        Returns:
            pandas.DataFrame: Behavioral features
        """
        self.logger.info("Extracting behavioral features")
       
        behavioral_features = pd.DataFrame()
       
        # If flow data is available, use that for behavioral analysis
        if flow_df is not None and not flow_df.empty:
            # Create a copy
            result = flow_df.copy()
           
            # Calculate packet rate variability (coefficient of variation)
            if 'length_count' in result.columns and 'length_std' in result.columns and 'length_mean' in result.columns:
                result['packet_rate_cv'] = result['length_std'] / result['length_mean']
           
            # Calculate byte rate variability
            if 'length_sum' in result.columns and 'length_mean' in result.columns:
                result['byte_per_packet_mean'] = result['length_sum'] / result['length_count']
               
            # Flag flows with unusual packet counts
            if 'length_count' in result.columns:
                # Flag flows with very high packet counts (potential DoS)
                high_packet_threshold = result['length_count'].quantile(0.95)
                result['high_packet_count'] = result['length_count'] > high_packet_threshold
               
                # Flag flows with very low packet counts (potential scan)
                result['low_packet_count'] = result['length_count'] == 1
           
            # Flag flows with unusual byte rates
            if 'byte_rate' in result.columns:
                high_byte_threshold = result['byte_rate'].quantile(0.95)
                result['high_byte_rate'] = result['byte_rate'] > high_byte_threshold
           
            behavioral_features = result
       
        # Otherwise use the packet data directly
        elif not df.empty:
            # Create a copy
            result = df.copy()
           
            # Check for port scanning behavior (many dst ports, few packets per port)
            if 'src_ip' in result.columns and 'dst_port' in result.columns:
                # Count unique destination ports per source IP
                port_counts = result.groupby('src_ip')['dst_port'].nunique().reset_index()
                port_counts.columns = ['src_ip', 'unique_dst_ports']
               
                # Count packets per source IP
                packet_counts = result.groupby('src_ip').size().reset_index()
                packet_counts.columns = ['src_ip', 'packet_count']
               
                # Combine counts
                ip_stats = port_counts.merge(packet_counts, on='src_ip')
               
                # Calculate ports-to-packets ratio (higher indicates potential scanning)
                ip_stats['port_scan_ratio'] = ip_stats['unique_dst_ports'] / ip_stats['packet_count']
               
                # Flag potential port scanners
                ip_stats['potential_scanner'] = ip_stats['port_scan_ratio'] > 0.5
               
                # Merge back to result
                behavioral_features = ip_stats
       
        return behavioral_features
   
    def select_important_features(self, X, y=None, k=10):
        """
        Select important features for anomaly detection.
       
        Args:
            X (pandas.DataFrame): Input features
            y (pandas.Series): Target labels (optional)
            k (int): Number of features to select
           
        Returns:
            pandas.DataFrame: Selected features
        """
        self.logger.info(f"Selecting top {k} important features")
       
        if y is not None:
            # Use feature selection with labels
            selector = SelectKBest(f_classif, k=min(k, X.shape[1]))
            X_selected = selector.fit_transform(X, y)
           
            # Get selected feature names
            mask = selector.get_support()
            selected_features = X.columns[mask]
           
            self.logger.info(f"Selected features: {', '.join(selected_features)}")
           
            return X[selected_features]
        else:
            # Use PCA for dimensionality reduction without labels
            pca = PCA(n_components=min(k, X.shape[1]))
            X_pca = pca.fit_transform(X)
           
            # Create DataFrame with PCA components
            pca_df = pd.DataFrame(
                X_pca,
                columns=[f'PC{i+1}' for i in range(X_pca.shape[1])]
            )
           
            # Log explained variance
            explained_variance = pca.explained_variance_ratio_ * 100
            self.logger.info(f"PCA explained variance: {explained_variance.sum():.2f}% with {X_pca.shape[1]} components")
           
            return pca_df
   
    def extract_all_features(self, df, flow_df=None, extract_network=True, extract_temporal=True,
                             extract_behavioral=True, select_features=False, k=10):
        """
        Extract all types of features and combine them.
       
        Args:
            df (pandas.DataFrame): Input data
            flow_df (pandas.DataFrame): Flow features data if available
            extract_network (bool): Whether to extract network graph features
            extract_temporal (bool): Whether to extract temporal features
            extract_behavioral (bool): Whether to extract behavioral features
            select_features (bool): Whether to select important features
            k (int): Number of features to select if select_features is True
           
        Returns:
            pandas.DataFrame: Combined features
        """
        self.logger.info("Extracting all features")
       
        feature_dfs = []
       
        # Extract port features
        port_features = self.extract_port_features(df)
        if not port_features.empty:
            feature_dfs.append(port_features)
       
        # Extract protocol distribution
        protocol_features = self.extract_protocol_distribution(df)
        if not protocol_features.empty:
            feature_dfs.append(protocol_features)
       
        # Extract network graph features
        if extract_network:
            network_features = self.extract_network_graph_features(df)
            if not network_features.empty:
                feature_dfs.append(network_features)
       
        # Extract temporal features
        if extract_temporal:
            temporal_features = self.extract_temporal_features(df)
            if not temporal_features.empty:
                feature_dfs.append(temporal_features)
       
        # Extract behavioral features
        if extract_behavioral:
            behavioral_features = self.extract_behavioral_features(df, flow_df)
            if not behavioral_features.empty:
                feature_dfs.append(behavioral_features)
       
        # Combine all features
        if not feature_dfs:
            self.logger.warning("No features extracted")
            return pd.DataFrame()
       
        # Attempt to combine all feature dataframes
        combined_features = pd.concat(feature_dfs, axis=1)
       
        # Select important features if requested
        if select_features and not combined_features.empty:
            # Remove non-numeric columns
            numeric_features = combined_features.select_dtypes(include=['int64', 'float64'])
            if not numeric_features.empty:
                return self.select_important_features(numeric_features, k=k)
       
        return combined_features
   
    def save_features(self, features_df, output_file=None):
        """
        Save extracted features to file.
       
        Args:
            features_df (pandas.DataFrame): Features DataFrame
            output_file (str): Filename for output features
           
        Returns:
            str: Path to saved features file
        """
        if features_df.empty:
            self.logger.warning("No features to save")
            return None
       
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_extracted_features.csv"
       
        output_path = os.path.join(self.output_dir, output_file)
       
        try:
            features_df.to_csv(output_path, index=False)
            self.logger.info(f"Saved {features_df.shape[1]} features for {features_df.shape[0]} samples to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error saving features: {str(e)}")
            return None


def main():
    """
    Main function to run the feature extractor module.
    """
    parser = argparse.ArgumentParser(description="Network Traffic Feature Extractor")
    parser.add_argument("--input", "-i", help="Input CSV file with processed data")
    parser.add_argument("--flow-input", "-f", help="Input CSV file with flow data (optional)")
    parser.add_argument("--output", "-o", help="Output directory", default="../data/processed")
    parser.add_argument("--select", "-s", action="store_true", help="Select important features")
    parser.add_argument("--k", "-k", type=int, default=10, help="Number of features to select")
   
    args = parser.parse_args()
   
    extractor = FeatureExtractor(
        input_dir=os.path.dirname(args.input) if args.input else "../data/processed",
        output_dir=args.output
    )
   
    # Load input data
    df = None
    if args.input:
        df = pd.read_csv(args.input)
        print(f"Loaded {len(df)} records from {args.input}")
    else:
        print("No input file specified")
        sys.exit(1)
   
    # Load flow data if provided
    flow_df = None
    if args.flow_input:
        flow_df = pd.read_csv(args.flow_input)
        print(f"Loaded {len(flow_df)} flow records from {args.flow_input}")
   
    # Extract all features
    features_df = extractor.extract_all_features(
        df,
        flow_df=flow_df,
        select_features=args.select,
        k=args.k
    )
   
    # Save features
    if not features_df.empty:
        extractor.save_features(features_df)
    else:
        print("No features extracted")
        sys.exit(1)

if __name__ == "__main__":
    main()
