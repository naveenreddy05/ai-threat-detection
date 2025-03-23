import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime
import time

# Add src directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from src.data_ingestion.network_capture import NetworkCapture
from src.data_ingestion.data_preprocessor import DataPreprocessor
from src.model.anomaly_detector import AnomalyDetector
from src.visualization.traffic_visualization import TrafficVisualizer

print("AI-Driven Threat Detection System - Hackathon Demo")
print("=" * 50)

# 1. Create directories if they don't exist
for directory in ['data/raw', 'data/processed', 'data/models', 'data/results']:
    if not os.path.exists(directory):
        os.makedirs(directory)
print("✅ Initialized directories")

# 2. Create sample data (since we're on Windows, direct capture is difficult)
print("Creating sample network traffic data...")
# Create some sample data
sample_data = {
    'timestamp': [time.time() - i for i in range(100)],
    'length': np.random.randint(60, 1500, 100),
    'protocol': np.random.choice(['TCP', 'UDP', 'ICMP', 'HTTP'], 100),
    'src_ip': ['192.168.1.' + str(np.random.randint(1, 255)) for _ in range(100)],
    'dst_ip': ['10.0.0.' + str(np.random.randint(1, 255)) for _ in range(100)],
    'src_port': np.random.randint(1024, 65535, 100),
    'dst_port': np.random.randint(1, 1024, 100),
    'ttl': np.random.randint(32, 128, 100),
}
df = pd.DataFrame(sample_data)
# Add some anomalies
anomaly_indices = np.random.choice(range(100), 5, replace=False)
for idx in anomaly_indices:
    df.loc[idx, 'length'] = 9999  # Unusually large packet
    df.loc[idx, 'dst_port'] = 31337  # Suspicious port
   
# Save to CSV
pcap_path = os.path.join('data/raw', 'sample_data.csv')
df.to_csv(pcap_path, index=False)
print(f"✅ Created sample data at {pcap_path}")

# 3. Extract features
print("Extracting features...")
df = pd.read_csv(pcap_path)
print(f"✅ Extracted features from {len(df)} packets")

# 4. Preprocess data
print("Preprocessing data...")
preprocessor = DataPreprocessor()
try:
    # Add the 'processed_time' column to the DataFrame
    df['processed_time'] = pd.Timestamp.now()
   
    # Try full preprocessing
    X_processed, enriched_df, flow_df = preprocessor.preprocess_data(df, extract_flow=True)
    print(f"✅ Preprocessed data with shape {X_processed.shape}")
except Exception as e:
    print(f"❌ Error preprocessing: {str(e)}")
    # Create simple features
    numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
   
    # Remove timestamp from numeric columns if present
    if 'timestamp' in numeric_cols:
        numeric_cols.remove('timestamp')
   
    if not numeric_cols:
        # If no numeric columns, create some
        df['length_normalized'] = df['length'] / df['length'].max()
        df['port_ratio'] = df['src_port'] / df['dst_port']
        numeric_cols = ['length_normalized', 'port_ratio']
   
    X_processed = df[numeric_cols].values
    enriched_df = df
    flow_df = None
    print("✅ Using basic features instead")

# 5. Train anomaly detection model (or load existing)
print("Training anomaly detection model...")
model = AnomalyDetector(model_type='isolation_forest')
model.fit(X_processed)
print("✅ Model trained successfully")

# 6. Make predictions
print("Detecting anomalies...")
predictions = model.predict(X_processed)
scores = model.decision_function(X_processed)

# Add predictions to dataframe
enriched_df['prediction'] = predictions
enriched_df['anomaly_score'] = scores
enriched_df['is_anomaly'] = predictions == -1

anomaly_count = (predictions == -1).sum()
print(f"✅ Detected {anomaly_count} anomalies out of {len(predictions)} packets")

# 7. Save model
print("Saving model...")
model_path = model.save_model()
print(f"✅ Model saved to {model_path}")

# 8. Create visualizations
print("Creating visualizations...")
visualizer = TrafficVisualizer()

# Ensure results directory exists
if not os.path.exists('data/results'):
    os.makedirs('data/results')

try:
    # Traffic volume visualization
    viz_path1 = visualizer.plot_traffic_volume(
        enriched_df,
        output_file="traffic_volume.png"
    )
   
    # Protocol distribution
    viz_path2 = visualizer.plot_protocol_distribution(
        enriched_df,
        output_file="protocol_dist.png"
    )
   
    # Anomaly timeline
    viz_path3 = visualizer.plot_anomaly_timeline(
        enriched_df,
        is_anomaly_col='is_anomaly',
        score_col='anomaly_score',
        output_file="anomaly_timeline.png"
    )
   
    print(f"✅ Created visualizations:")
    print(f"  - {viz_path1}")
    print(f"  - {viz_path2}")
    print(f"  - {viz_path3}")
except Exception as e:
    print(f"❌ Error creating visualizations: {str(e)}")
    print("This is expected if running without a display or with limited plotting capabilities.")

# 9. Show results
print("\nRESULTS SUMMARY:")
print(f"Total packets analyzed: {len(enriched_df)}")
print(f"Anomalies detected: {anomaly_count} ({anomaly_count/len(enriched_df)*100:.2f}%)")

if anomaly_count > 0:
    print("\nTop anomalies:")
    anomalies = enriched_df[enriched_df['is_anomaly'] == True].sort_values('anomaly_score')
    for i, (_, row) in enumerate(anomalies.iterrows()):
        if i >= 5:  # Show top 5
            break
        print(f"  - Src: {row['src_ip']} → Dst: {row['dst_ip']} ({row['protocol']}, score: {row['anomaly_score']:.4f})")

print("\n✅ Demo completed successfully!")
print("To run the dashboard: python -m src.visualization.alert_dashboard")
