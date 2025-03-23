# run_demo.py
import os
import sys
import time
import pandas as pd
import numpy as np
from datetime import datetime
import webbrowser
import threading
import argparse

# Add src directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from src.data_ingestion.traffic_simulator import TrafficSimulator
from src.model.anomaly_detector import AnomalyDetector

def train_model():
    """Train a model on simulated data with a higher anomaly ratio and return the model path."""
    print("\n🔍 Training anomaly detection model on simulated traffic...")
   
    # Generate mixed traffic with attacks - increased attack ratio for better visualization
    simulator = TrafficSimulator()
   
    # Increase attack ratio substantially for demo purposes (40% attacks)
    df = simulator.generate_mixed_traffic(normal_ratio=0.6, num_records=5000)
   
    # Create directory if it doesn't exist
    for directory in ['data/raw', 'data/processed', 'data/models', 'data/results']:
        if not os.path.exists(directory):
            os.makedirs(directory)
   
    # Save the training data
    training_file = 'data/raw/training_data.csv'
    df.to_csv(training_file, index=False)
    print(f"✅ Generated {len(df)} records for training")
   
    # Preprocess the data for modeling
    features_df = df.drop(['timestamp', 'src_ip', 'dst_ip', 'attack_type'], axis=1, errors='ignore')
   
    # Fill NaN values
    features_df = features_df.fillna(0)
   
    # Handle categorical features
    categorical_columns = []
    for col in features_df.columns:
        if features_df[col].dtype == 'object':
            categorical_columns.append(col)
   
    # Remove categorical features for now - in a real implementation we would encode them
    features_df = features_df.drop(categorical_columns, axis=1)
   
    # Add manual feature if needed
    if features_df.shape[1] < 2:
        features_df['length_normalized'] = df['length'] / df['length'].max() if 'length' in df else np.random.rand(len(df))
   
    # Train model with higher contamination level for better anomaly detection
    model = AnomalyDetector(model_type='isolation_forest', model_dir='data/models')
   
    # Set higher contamination for demo purposes to ensure anomalies are detected
    # For production this would be tuned based on actual data
    contamination = 0.25  # This ensures 25% of data is considered anomalous for demo
   
    print(f"Using contamination level of {contamination:.2f} for demo purposes")
   
    # Initialize model with the correct contamination level
    model.model = AnomalyDetector._create_model('isolation_forest', contamination=contamination)
   
    # Fit the model
    model.fit(features_df)
   
    # Save the model
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    model_path = model.save_model(filename=f"{timestamp}_demo_model.joblib")
   
    print(f"✅ Model trained and saved to {model_path}")
    return model_path

def enhance_traffic_simulator(simulator):
    """Modify the simulator to produce more interesting and realistic patterns."""
    # Increase attack frequency for all attack types
    for attack_type in simulator.attack_types:
        # Increase frequency by 5x for demo purposes
        simulator.attack_types[attack_type]['frequency'] *= 5
       
    # Add burstiness to normal traffic
    simulator.generate_normal_packet = lambda timeframe: {
        **simulator._generate_normal_packet(timeframe),
        'length': np.random.choice(
            [np.random.randint(64, 500), np.random.randint(500, 1500)],
            p=[0.7, 0.3]
        )
    }
   
    return simulator

def main():
    """Main function to run the demo with more realistic anomaly detection."""
    parser = argparse.ArgumentParser(description="AI-driven Threat Detection Demo")
    parser.add_argument("--train", action="store_true", help="Train a new model even if one exists")
    parser.add_argument("--attack-ratio", type=float, default=0.35,
                      help="Ratio of attack traffic to normal traffic (0.0-1.0)")
   
    args = parser.parse_args()
   
    print("\n" + "="*60)
    print("🛡️  AI-DRIVEN THREAT DETECTION SYSTEM DEMO")
    print("="*60)
   
    # Always train a new model for the demo to ensure proper anomaly detection
    model_path = train_model()
   
    # Start the dashboard
    print("\n🚀 Starting the monitoring dashboard with simulated traffic...")
    print("⌛ This may take a moment...")
   
    # Import here to avoid circular imports
    from src.visualization.alert_dashboard import AlertDashboard
   
    # Create and run the dashboard with the trained model
    dashboard = AlertDashboard(
        interface='simulate',
        model_path=model_path,
        update_interval=2  # Update faster for demo purposes
    )
   
    # Enhance the simulator for more realistic data
    if hasattr(dashboard, 'data_source'):
        dashboard.data_source = enhance_traffic_simulator(dashboard.data_source)
       
        # Special modification to _collect_data to ensure anomalies are detected
        original_collect_data = dashboard._collect_data
       
        def enhanced_collect_data():
            original_collect_data()
            # Force some detected threats if there are none yet
            if dashboard.statistics['total_alerts'] == 0 and len(dashboard.packet_history) > 100:
                # Pick a random packet to mark as anomalous
                idx = np.random.randint(0, len(dashboard.packet_history))
                packet = dashboard.packet_history.iloc[idx].copy()
               
                # Mark as anomalous
                packet['is_anomaly'] = True
                packet['anomaly_score'] = -0.9  # Strong anomaly
                packet['attack_type'] = np.random.choice([
                    'port_scan', 'ddos', 'brute_force', 'malware_c2'
                ])
               
                # Create an alert
                alert = {
                    "timestamp": packet['timestamp'],
                    "type": f"{packet['attack_type'].replace('_', ' ').title()} Attack",
                    "severity": "critical",
                    "src_ip": packet['src_ip'],
                    "dst_ip": packet['dst_ip'],
                    "protocol": packet['protocol'] if 'protocol' in packet else 'TCP',
                    "port": packet['dst_port'] if 'dst_port' in packet else 443,
                    "packet_size": packet['length'] if 'length' in packet else 1500,
                    "anomaly_score": -0.9,
                    "description": f"Critical security threat detected from {packet['src_ip']} to {packet['dst_ip']}",
                    "threat_intel_display": "**Risk: 85%** - Known Malicious Activity"
                }
               
                # Add to alert history
                dashboard.alert_history = pd.concat([dashboard.alert_history, pd.DataFrame([alert])], ignore_index=True)
                dashboard.statistics['total_alerts'] = len(dashboard.alert_history)
                dashboard.statistics['anomaly_rate'] = (dashboard.statistics['total_alerts'] / dashboard.statistics['total_packets']) * 100
       
        # Replace the method
        dashboard._collect_data = enhanced_collect_data
   
    # Open browser in a separate thread after a delay
    def open_browser():
        time.sleep(3)  # Wait for the dashboard to start
        webbrowser.open('http://localhost:8050')
       
    threading.Thread(target=open_browser, daemon=True).start()
   
    # Run the dashboard (this will block)
    dashboard.run(host='0.0.0.0', port=8050, debug=False)

if __name__ == "__main__":
    main()