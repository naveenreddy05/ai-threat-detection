# Path: main.py
import os
import sys
import argparse
import logging
import configparser
import threading
import time

# Add src directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from src.data_ingestion.network_capture import NetworkCapture
from src.data_ingestion.data_preprocessor import DataPreprocessor
from src.feature_engineering.feature_extractor import FeatureExtractor
from src.model.anomaly_detector import AnomalyDetector
from src.model.model_trainer import ModelTrainer
from src.visualization.traffic_visualization import TrafficVisualizer
from src.visualization.alert_dashboard import AlertDashboard
from src.api.routes import app as api_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ai_threat_detection.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from config file."""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.ini')
   
    if os.path.exists(config_path):
        config.read(config_path)
        logger.info(f"Loaded configuration from {config_path}")
    else:
        logger.warning(f"Configuration file not found at {config_path}, using defaults")
   
    return config

def run_api(config):
    """Run the API server."""
    host = config.get('API', 'host', fallback='0.0.0.0')
    port = config.getint('API', 'port', fallback=5000)
    debug = config.getboolean('DEFAULT', 'debug', fallback=False)
   
    logger.info(f"Starting API server on {host}:{port}")
    api_app.run(host=host, port=port, debug=debug)

def run_dashboard(config):
    """Run the alert dashboard."""
    interface = config.get('NETWORK', 'default_interface', fallback=None)
    models_dir = config.get('SYSTEM', 'models_dir', fallback='data/models')
   
    # Get the latest model
    model_path = None
    if os.path.exists(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib')]
        if model_files:
            model_files.sort(reverse=True)
            model_path = os.path.join(models_dir, model_files[0])
   
    # Start dashboard
    dashboard = AlertDashboard(
        interface=interface,
        model_path=model_path,
        update_interval=10
    )
   
    dashboard.run(host='0.0.0.0', port=8050, debug=False)

def train_model(config):
    """Train a new anomaly detection model."""
    model_type = config.get('MODEL', 'default_model_type', fallback='isolation_forest')
    use_pca = config.getboolean('MODEL', 'use_pca', fallback=True)
   
    logger.info(f"Training new {model_type} model")
   
    trainer = ModelTrainer()
    model, metrics = trainer.run_training_pipeline(
        model_type=model_type,
        use_pca=use_pca
    )
   
    if model:
        logger.info(f"Successfully trained model with metrics: {metrics}")
        return True
    else:
        logger.error("Model training failed")
        return False

def capture_and_detect(config):
    """Capture network traffic and perform anomaly detection."""
    interface = config.get('NETWORK', 'default_interface', fallback=None)
    duration = config.getint('NETWORK', 'capture_duration', fallback=60)
    packet_count = config.getint('NETWORK', 'packet_count', fallback=1000)
    models_dir = config.get('SYSTEM', 'models_dir', fallback='data/models')
    results_dir = config.get('SYSTEM', 'results_dir', fallback='data/results')
   
    # Ensure directories exist
    for directory in [models_dir, results_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)
   
    # Get the latest model
    model_path = None
    if os.path.exists(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith('.joblib')]
        if model_files:
            model_files.sort(reverse=True)
            model_path = os.path.join(models_dir, model_files[0])
   
    if not model_path:
        logger.error("No trained model found. Please train a model first.")
        return False
   
    # Load model
    model = AnomalyDetector().load_model(model_path)
    if not model:
        logger.error(f"Failed to load model from {model_path}")
        return False
   
    logger.info(f"Loaded model from {model_path}")
   
    # Initialize components
    capture = NetworkCapture(interface=interface)
    preprocessor = DataPreprocessor()
    visualizer = TrafficVisualizer(output_dir=results_dir)
   
    # Capture packets
    logger.info(f"Capturing packets from {interface} for {duration} seconds")
    pcap_path = capture.capture_live(duration=duration, packet_count=packet_count)
   
    if not pcap_path:
        logger.error("Packet capture failed")
        return False
   
    # Read and process packets
    packets = capture.read_pcap(pcap_path)
    if not packets:
        logger.error("No packets captured")
        return False
   
    # Extract basic features
    df = capture.extract_basic_features(packets)
    if df.empty:
        logger.error("Failed to extract features from packets")
        return False
   
    # Preprocess data
    X_processed, enriched_df, flow_df = preprocessor.preprocess_data(df, extract_flow=True)
   
    # Make predictions
    predictions = model.predict(X_processed)
    scores = model.decision_function(X_processed)
   
    # Create results dataframe
    results_df = pd.DataFrame({
        'timestamp': enriched_df['timestamp'],
        'src_ip': enriched_df['src_ip'],
        'dst_ip': enriched_df['dst_ip'],
        'protocol': enriched_df['protocol'],
        'length': enriched_df['length'],
        'prediction': predictions,
        'anomaly_score': scores,
        'is_anomaly': predictions == -1
    })
   
    # Save results
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    results_path = os.path.join(results_dir, f"{timestamp}_detection_results.csv")
    results_df.to_csv(results_path, index=False)
   
    # Count anomalies
    anomaly_count = (predictions == -1).sum()
    logger.info(f"Detected {anomaly_count} anomalies out of {len(predictions)} packets")
   
    # Create visualizations
    viz_path = visualizer.plot_anomaly_timeline(
        results_df,
        time_col='timestamp',
        is_anomaly_col='is_anomaly',
        score_col='anomaly_score',
        output_file=f"{timestamp}_anomaly_timeline.html",
        interactive=True
    )
   
    if viz_path:
        logger.info(f"Saved visualization to {viz_path}")
   
    return True

def main():
    """Main function to run the AI Threat Detection system."""
    parser = argparse.ArgumentParser(description="AI-driven Threat Detection System")
    parser.add_argument("--mode", "-m", choices=["api", "dashboard", "train", "detect", "all"],
                        default="all", help="Operation mode")
    parser.add_argument("--config", "-c", help="Path to config file")
   
    args = parser.parse_args()
   
    # Load configuration
    config = load_config()
    if args.config:
        if os.path.exists(args.config):
            config.read(args.config)
            logger.info(f"Loaded custom configuration from {args.config}")
        else:
            logger.error(f"Custom config file not found: {args.config}")
   
    if args.mode == "api":
        run_api(config)
    elif args.mode == "dashboard":
        run_dashboard(config)
    elif args.mode == "train":
        train_model(config)
    elif args.mode == "detect":
        capture_and_detect(config)
    else:  # all
        try:
            # Start API in a separate thread
            api_thread = threading.Thread(target=run_api, args=(config,))
            api_thread.daemon = True
            api_thread.start()
           
            # Check if we have a trained model, if not train one
            models_dir = config.get('SYSTEM', 'models_dir', fallback='data/models')
            if not os.path.exists(models_dir) or not any(f.endswith('.joblib') for f in os.listdir(models_dir)):
                logger.info("No trained model found. Training a new model...")
                train_model(config)
           
            # Run the dashboard (this will block)
            run_dashboard(config)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error(f"Error in main: {str(e)}")

if __name__ == "__main__":
    main()
