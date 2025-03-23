 
import os
import sys
import logging
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib

class DataPreprocessor:
    """
    Class for preprocessing network traffic data for anomaly detection.
    """
    def __init__(self, input_dir="../data/raw", output_dir="../data/processed"):
        """
        Initialize DataPreprocessor.
        
        Args:
            input_dir (str): Directory containing raw data
            output_dir (str): Directory to save processed data
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
        
        # Initialize preprocessing pipeline
        self.preprocessing_pipeline = None
        
    def load_data(self, file_path=None):
        """
        Load data from CSV file.
        
        Args:
            file_path (str): Path to CSV file (if None, loads most recent in input_dir)
            
        Returns:
            pandas.DataFrame: Loaded data
        """
        if not file_path:
            # Find most recent CSV file in input_dir
            csv_files = [f for f in os.listdir(self.input_dir) if f.endswith('.csv')]
            if not csv_files:
                self.logger.error(f"No CSV files found in {self.input_dir}")
                return pd.DataFrame()
                
            csv_files.sort(reverse=True)  # Sort by filename (assumes timestamp-based naming)
            file_path = os.path.join(self.input_dir, csv_files[0])
        
        try:
            self.logger.info(f"Loading data from {file_path}")
            df = pd.read_csv(file_path)
            self.logger.info(f"Loaded {len(df)} records with {df.shape[1]} features")
            return df
        except Exception as e:
            self.logger.error(f"Error loading data: {str(e)}")
            return pd.DataFrame()
        
    def create_preprocessing_pipeline(self, df):
        """
        Create preprocessing pipeline based on the data structure.
        
        Args:
            df (pandas.DataFrame): Input data
            
        Returns:
            sklearn.pipeline.Pipeline: Preprocessing pipeline
        """
        self.logger.info("Creating preprocessing pipeline")
        
        # Identify column types
        numeric_features = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
        categorical_features = df.select_dtypes(include=['object']).columns.tolist()
        
        # Remove timestamp and IP addresses from preprocessing
        if 'timestamp' in numeric_features:
            numeric_features.remove('timestamp')
        
        if 'src_ip' in categorical_features:
            categorical_features.remove('src_ip')
        
        if 'dst_ip' in categorical_features:
            categorical_features.remove('dst_ip')
        
        # Define preprocessing for numerical features
        numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])
        
        # Define preprocessing for categorical features
        categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='unknown')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        # Combine preprocessing steps
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, numeric_features),
                ('cat', categorical_transformer, categorical_features)
            ]
        )
        
        # Create and return the preprocessing pipeline
        self.preprocessing_pipeline = Pipeline(steps=[
            ('preprocessor', preprocessor)
        ])
        
        return self.preprocessing_pipeline
    
    def extract_time_features(self, df):
        """
Extract time-based features from timestamp.
        
        Args:
            df (pandas.DataFrame): Input data with timestamp column
            
        Returns:
            pandas.DataFrame: Data with additional time-based features
        """
        if 'timestamp' not in df.columns:
            self.logger.warning("No timestamp column found for time feature extraction")
            return df
        
        self.logger.info("Extracting time-based features")
        
        # Create a copy to avoid modifying the original
        result = df.copy()
        
        # Convert timestamp to datetime
        result['datetime'] = pd.to_datetime(result['timestamp'], unit='s')
        
        # Extract time-based features
        result['hour'] = result['datetime'].dt.hour
        result['day_of_week'] = result['datetime'].dt.dayofweek
        result['is_weekend'] = result['datetime'].dt.dayofweek >= 5
        result['is_night'] = (result['hour'] < 6) | (result['hour'] >= 20)
        
        # Drop temporary datetime column
        result = result.drop('datetime', axis=1)
        
        return result
    
    def extract_flow_features(self, df, window_size=60):
        """
        Extract flow-based features within time windows.
        
        Args:
            df (pandas.DataFrame): Input data
            window_size (int): Time window size in seconds
            
        Returns:
            pandas.DataFrame: Aggregated flow features
        """
        if 'timestamp' not in df.columns or 'src_ip' not in df.columns or 'dst_ip' not in df.columns:
            self.logger.warning("Required columns missing for flow feature extraction")
            return df
        
        self.logger.info(f"Extracting flow-based features with {window_size}s window")
        
        # Create a copy and ensure timestamp is sorted
        result = df.copy().sort_values('timestamp')
        
        # Create flow identifiers (source IP + destination IP)
        result['flow'] = result['src_ip'] + '->' + result['dst_ip']
        
        # Create time windows
        result['time_window'] = (result['timestamp'] // window_size) * window_size
        
        # Group by flow and time window
        flow_features = result.groupby(['flow', 'time_window']).agg({
            'length': ['count', 'mean', 'std', 'min', 'max', 'sum'],
            'protocol': 'nunique',
            'src_port': 'nunique',
            'dst_port': 'nunique'
        })
        
        # Flatten column names
        flow_features.columns = ['_'.join(col).strip() for col in flow_features.columns.values]
        flow_features = flow_features.reset_index()
        
        # Calculate packet rate (packets per second)
        flow_features['packet_rate'] = flow_features['length_count'] / window_size
        
        # Calculate byte rate (bytes per second)
        flow_features['byte_rate'] = flow_features['length_sum'] / window_size
        
        return flow_features
    
    def preprocess_data(self, df, create_pipeline=True, extract_time=True, extract_flow=True, flow_window=60):
        """
        Preprocess data for anomaly detection.
        
        Args:
            df (pandas.DataFrame): Input data
            create_pipeline (bool): Whether to create a new preprocessing pipeline
            extract_time (bool): Whether to extract time-based features
            extract_flow (bool): Whether to extract flow-based features
            flow_window (int): Time window size for flow features
            
        Returns:
            tuple: (Preprocessed data, original data with additional features)
        """
        if df.empty:
            self.logger.warning("Empty DataFrame provided for preprocessing")
            return df, df
        
        self.logger.info("Starting data preprocessing")
        
        # Step 1: Extract additional features
        enriched_df = df.copy()
        
        if extract_time:
            enriched_df = self.extract_time_features(enriched_df)
            
        if extract_flow:
            flow_df = self.extract_flow_features(enriched_df, window_size=flow_window)
            # We return flow_df separately as it's already aggregated
            
        # Step 2: Handle IP addresses for analysis (convert to categorical or numeric representation)
        if 'src_ip' in enriched_df.columns and 'dst_ip' in enriched_df.columns:
            # Create a column indicating if source and dest IPs are in the same subnet
            enriched_df['same_subnet'] = enriched_df.apply(
                lambda row: row['src_ip'].split('.')[0:3] == row['dst_ip'].split('.')[0:3], 
                axis=1
            )
            
        # Step 3: Apply preprocessing pipeline
        if create_pipeline or self.preprocessing_pipeline is None:
            self.create_preprocessing_pipeline(enriched_df)
        
        # Select features for preprocessing (exclude non-feature columns)
        features_df = enriched_df.drop(['timestamp', 'src_ip', 'dst_ip'], axis=1, errors='ignore')
        
        # Apply preprocessing
        try:
            X_processed = self.preprocessing_pipeline.fit_transform(features_df)
            self.logger.info(f"Preprocessed data shape: {X_processed.shape}")
            
            if extract_flow:
                return X_processed, enriched_df, flow_df
            else:
                return X_processed, enriched_df
                
        except Exception as e:
            self.logger.error(f"Error during preprocessing: {str(e)}")
            return None, enriched_df
    
    def save_processed_data(self, X_processed, enriched_df, flow_df=None, output_file=None):
        """
        Save processed data.
        
        Args:
            X_processed: Preprocessed features
            enriched_df (pandas.DataFrame): Original data with additional features
            flow_df (pandas.DataFrame): Flow-based features
            output_file (str): Filename prefix for output files (default: timestamp-based)
            
        Returns:
            dict: Paths to saved files
        """
        # Generate default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_processed"
        
        result = {}
        
        try:
            # Save preprocessed features
            if X_processed is not None:
                features_path = os.path.join(self.output_dir, f"{output_file}_features.npz")
                np.savez_compressed(features_path, X=X_processed)
                result['features'] = features_path
                self.logger.info(f"Saved preprocessed features to {features_path}")
            
            # Save enriched dataframe
            if not enriched_df.empty:
                enriched_path = os.path.join(self.output_dir, f"{output_file}_enriched.csv")
                enriched_df.to_csv(enriched_path, index=False)
                result['enriched'] = enriched_path
                self.logger.info(f"Saved enriched data to {enriched_path}")
            
            # Save flow features
            if flow_df is not None and not flow_df.empty:
                flow_path = os.path.join(self.output_dir, f"{output_file}_flows.csv")
                flow_df.to_csv(flow_path, index=False)
                result['flows'] = flow_path
                self.logger.info(f"Saved flow features to {flow_path}")
            
            # Save preprocessing pipeline
            if self.preprocessing_pipeline is not None:
                pipeline_path = os.path.join(self.output_dir, f"{output_file}_pipeline.joblib")
                joblib.dump(self.preprocessing_pipeline, pipeline_path)
                result['pipeline'] = pipeline_path
                self.logger.info(f"Saved preprocessing pipeline to {pipeline_path}")
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error saving processed data: {str(e)}")
            return result
def main():
    """
    Main function to run the data preprocessor module.
    """
    parser = argparse.ArgumentParser(description="Network Traffic Data Preprocessor")
    parser.add_argument("--input", "-i", help="Input CSV file or directory")
    parser.add_argument("--output", "-o", help="Output directory", default="../data/processed")
    parser.add_argument("--flow-window", "-w", type=int, default=60, help="Time window for flow features (seconds)")
    
    args = parser.parse_args()
    
    preprocessor = DataPreprocessor(
        input_dir=os.path.dirname(args.input) if args.input and os.path.isfile(args.input) else "../data/raw",
        output_dir=args.output
    )
    
    # Load data
    df = preprocessor.load_data(args.input)
    if df.empty:
        sys.exit(1)
    
    # Preprocess data
    X_processed, enriched_df, flow_df = preprocessor.preprocess_data(
        df, 
        extract_flow=True,
        flow_window=args.flow_window
    )
    
    # Save processed data
    preprocessor.save_processed_data(X_processed, enriched_df, flow_df)

if __name__== "__main__":
    main()