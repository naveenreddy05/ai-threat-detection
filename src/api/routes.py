# src/api/routes.py
import os
import sys
import logging
import json
import flask
from flask import Flask, request, jsonify, abort, send_file
from flask_cors import CORS
import pandas as pd
import numpy as np
from datetime import datetime
import joblib
import threading
import time

# Import from our modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_ingestion.network_capture import NetworkCapture
from data_ingestion.data_preprocessor import DataPreprocessor
from feature_engineering.feature_extractor import FeatureExtractor
from model.anomaly_detector import AnomalyDetector

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables
MODEL_DIR = "../data/models"
DATA_DIR = "../data/processed"
RESULTS_DIR = "../data/results"
ACTIVE_CAPTURES = {}
LOADED_MODELS = {}

# Helper functions
def get_latest_model():
    """Get the path to the latest model file."""
    model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith('.joblib')]
    if not model_files:
        return None
    model_files.sort(reverse=True)
    return os.path.join(MODEL_DIR, model_files[0])

def get_model(model_id):
    """Get or load a model by ID."""
    if model_id in LOADED_MODELS:
        return LOADED_MODELS[model_id]
   
    model_path = os.path.join(MODEL_DIR, model_id)
    if not os.path.exists(model_path):
        # Check if model_id is just the filename without path
        alt_path = os.path.join(MODEL_DIR, model_id + ".joblib")
        if not os.path.exists(alt_path):
            return None
        model_path = alt_path
   
    try:
        model = AnomalyDetector().load_model(model_path)
        LOADED_MODELS[model_id] = model
        return model
    except Exception as e:
        logger.error(f"Error loading model {model_id}: {str(e)}")
        return None

# API Routes
@app.route('/api/models', methods=['GET'])
def list_models():
    """List all available models."""
    try:
        model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith('.joblib')]
        models = []
       
        for model_file in model_files:
            model_path = os.path.join(MODEL_DIR, model_file)
            model_stat = os.stat(model_path)
           
            models.append({
                'id': model_file,
                'path': model_path,
                'size_bytes': model_stat.st_size,
                'created': datetime.fromtimestamp(model_stat.st_ctime).isoformat(),
                'last_modified': datetime.fromtimestamp(model_stat.st_mtime).isoformat()
            })
       
        return jsonify({
            'success': True,
            'models': models
        })
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/models/<model_id>', methods=['GET'])
def get_model_info(model_id):
    """Get information about a specific model."""
    try:
        model_path = os.path.join(MODEL_DIR, model_id)
        if not os.path.exists(model_path):
            return jsonify({
                'success': False,
                'error': f"Model {model_id} not found"
            }), 404
       
        model_stat = os.stat(model_path)
       
        # Load model to get additional information
        model = get_model(model_id)
        model_info = {
            'id': model_id,
            'path': model_path,
            'size_bytes': model_stat.st_size,
            'created': datetime.fromtimestamp(model_stat.st_ctime).isoformat(),
            'last_modified': datetime.fromtimestamp(model_stat.st_mtime).isoformat()
        }
       
        if model:
            model_info['model_type'] = model.model_type
       
        return jsonify({
            'success': True,
            'model': model_info
        })
    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/predict', methods=['POST'])
def predict():
    """Make predictions on submitted data."""
    try:
        # Check if required fields are in the request
        if not request.json:
            return jsonify({
                'success': False,
                'error': "Request must be JSON"
            }), 400
       
        # Get model ID or use latest
        model_id = request.json.get('model_id', None)
        if not model_id:
            model_path = get_latest_model()
            if not model_path:
                return jsonify({
                    'success': False,
                    'error': "No models available"
                }), 404
            model_id = os.path.basename(model_path)
       
        # Load model
        model = get_model(model_id)
        if not model:
            return jsonify({
                'success': False,
                'error': f"Model {model_id} not found or could not be loaded"
            }), 404
       
        # Get data from request
        data = request.json.get('data', None)
        if not data:
            return jsonify({
                'success': False,
                'error': "No data provided for prediction"
            }), 400
       
        # Convert data to DataFrame or numpy array
        try:
            if isinstance(data, list):
                # List of dictionaries or list of lists
                if isinstance(data[0], dict):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame(data)
            else:
                df = pd.DataFrame([data])
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f"Error parsing data: {str(e)}"
            }), 400
       
        # Make predictions
        predictions = model.predict(df)
        scores = model.decision_function(df)
       
        # Format results
        results = []
        for i in range(len(predictions)):
            results.append({
                'prediction': int(predictions[i]),
                'is_anomaly': int(predictions[i]) == -1,
                'anomaly_score': float(scores[i])
            })
       
        return jsonify({
            'success': True,
            'predictions': results,
            'model_id': model_id
        })
    except Exception as e:
        logger.error(f"Error making predictions: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start a new network capture."""
    try:
        # Check if required fields are in the request
        if not request.json:
            return jsonify({
                'success': False,
                'error': "Request must be JSON"
            }), 400
       
        interface = request.json.get('interface', None)
        if not interface:
            return jsonify({
                'success': False,
                'error': "Network interface must be specified"
            }), 400
       
        duration = request.json.get('duration', 60)
        packet_count = request.json.get('packet_count', 1000)
       
        # Generate capture ID
        capture_id = f"capture_{datetime.now().strftime('%Y%m%d%H%M%S')}"
       
        # Initialize capture object
        capture = NetworkCapture(interface=interface)
       
        # Start capture in a separate thread
        def run_capture():
            try:
                ACTIVE_CAPTURES[capture_id]['status'] = 'running'
                pcap_path = capture.capture_live(
                    duration=duration,
                    packet_count=packet_count
                )
               
                if pcap_path:
                    ACTIVE_CAPTURES[capture_id]['pcap_path'] = pcap_path
                    ACTIVE_CAPTURES[capture_id]['status'] = 'completed'
                   
                    # Extract features from captured packets
                    packets = capture.read_pcap(pcap_path)
                    if packets:
                        df = capture.extract_basic_features(packets)
                        features_path = capture.save_features(df)
                        ACTIVE_CAPTURES[capture_id]['features_path'] = features_path
                       
                        # Preprocess the data
                        preprocessor = DataPreprocessor()
                        X_processed, enriched_df, flow_df = preprocessor.preprocess_data(df, extract_flow=True)
                        processed_paths = preprocessor.save_processed_data(X_processed, enriched_df, flow_df)
                        ACTIVE_CAPTURES[capture_id].update(processed_paths)
                       
                        # Run anomaly detection if a model is available
                        latest_model = get_latest_model()
                        if latest_model:
                            model = get_model(os.path.basename(latest_model))
                            if model:
                                # Predict on processed data
                                predictions = model.predict(X_processed)
                                scores = model.decision_function(X_processed)
                               
                                # Store results
                                results_path = os.path.join(RESULTS_DIR, f"{capture_id}_results.csv")
                                results_df = pd.DataFrame({
                                    'timestamp': enriched_df['timestamp'],
                                    'prediction': predictions,
                                    'anomaly_score': scores,
                                    'is_anomaly': predictions == -1
                                })
                                results_df.to_csv(results_path, index=False)
                                ACTIVE_CAPTURES[capture_id]['results_path'] = results_path
                else:
                    ACTIVE_CAPTURES[capture_id]['status'] = 'failed'
            except Exception as e:
                logger.error(f"Error during capture {capture_id}: {str(e)}")
                ACTIVE_CAPTURES[capture_id]['status'] = 'failed'
                ACTIVE_CAPTURES[capture_id]['error'] = str(e)
       
        # Store capture info
        ACTIVE_CAPTURES[capture_id] = {
            'id': capture_id,
            'interface': interface,
            'duration': duration,
            'packet_count': packet_count,
            'start_time': datetime.now().isoformat(),
            'status': 'starting'
        }
       
        # Start the capture thread
        capture_thread = threading.Thread(target=run_capture)
        capture_thread.daemon = True
        capture_thread.start()
       
        return jsonify({
            'success': True,
            'capture_id': capture_id,
            'status': 'starting'
        })
    except Exception as e:
        logger.error(f"Error starting capture: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/capture/<capture_id>', methods=['GET'])
def get_capture_status(capture_id):
    """Get the status of a network capture."""
    try:
        if capture_id not in ACTIVE_CAPTURES:
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} not found"
            }), 404
       
        return jsonify({
            'success': True,
            'capture': ACTIVE_CAPTURES[capture_id]
        })
    except Exception as e:
        logger.error(f"Error getting capture status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/captures', methods=['GET'])
def list_captures():
    """List all captures."""
    try:
        return jsonify({
            'success': True,
            'captures': list(ACTIVE_CAPTURES.values())
        })
    except Exception as e:
        logger.error(f"Error listing captures: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/results/<capture_id>', methods=['GET'])
def get_capture_results(capture_id):
    """Get the results of a completed capture."""
    try:
        if capture_id not in ACTIVE_CAPTURES:
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} not found"
            }), 404
       
        capture_info = ACTIVE_CAPTURES[capture_id]
       
        if capture_info['status'] != 'completed':
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} is not completed (status: {capture_info['status']})"
            }), 400
       
        if 'results_path' not in capture_info:
            return jsonify({
                'success': False,
                'error': f"No results available for capture {capture_id}"
            }), 404
       
        # Read results file
        results_df = pd.read_csv(capture_info['results_path'])
       
        # Calculate summary statistics
        anomaly_count = int(results_df['is_anomaly'].sum())
        total_packets = len(results_df)
        anomaly_percent = (anomaly_count / total_packets * 100) if total_packets > 0 else 0
       
        # Return summary and detailed results
        return jsonify({
            'success': True,
            'summary': {
                'total_packets': total_packets,
                'anomaly_count': anomaly_count,
                'anomaly_percent': anomaly_percent,
                'capture_id': capture_id,
                'start_time': capture_info['start_time']
            },
            'results': results_df.to_dict(orient='records')
        })
    except Exception as e:
        logger.error(f"Error getting capture results: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/download/<capture_id>/<file_type>', methods=['GET'])
def download_capture_file(capture_id, file_type):
    """Download files related to a capture."""
    try:
        if capture_id not in ACTIVE_CAPTURES:
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} not found"
            }), 404
       
        capture_info = ACTIVE_CAPTURES[capture_id]
       
        # Define which file to download based on type
        file_path = None
        if file_type == 'pcap' and 'pcap_path' in capture_info:
            file_path = capture_info['pcap_path']
        elif file_type == 'features' and 'features_path' in capture_info:
            file_path = capture_info['features_path']
        elif file_type == 'results' and 'results_path' in capture_info:
            file_path = capture_info['results_path']
        else:
            return jsonify({
                'success': False,
                'error': f"File type '{file_type}' not available for this capture"
            }), 404
       
        if not file_path or not os.path.exists(file_path):
            return jsonify({
                'success': False,
                'error': f"File not found"
            }), 404
       
        # Return the file for download
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/visualization/<capture_id>/<viz_type>', methods=['GET'])
def get_visualization(capture_id, viz_type):
    """Generate and return visualizations for a capture."""
    try:
        from visualization.traffic_visualization import TrafficVisualizer
       
        if capture_id not in ACTIVE_CAPTURES:
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} not found"
            }), 404
       
        capture_info = ACTIVE_CAPTURES[capture_id]
       
        if capture_info['status'] != 'completed':
            return jsonify({
                'success': False,
                'error': f"Capture {capture_id} is not completed"
            }), 400
       
        # Check if we have the necessary data
        if 'features_path' not in capture_info:
            return jsonify({
                'success': False,
                'error': f"No feature data available for visualization"
            }), 404
       
        # Load the data
        df = pd.read_csv(capture_info['features_path'])
       
        # Initialize visualizer
        visualizer = TrafficVisualizer(output_dir=RESULTS_DIR)
       
        # Generate visualization based on type
        viz_path = None
        if viz_type == 'traffic_volume':
            viz_path = visualizer.plot_traffic_volume(df, interactive=True)
        elif viz_type == 'protocol_dist':
            viz_path = visualizer.plot_protocol_distribution(df, interactive=True)
        elif viz_type == 'network_graph':
            viz_path = visualizer.plot_network_graph(df, interactive=True)
        elif viz_type == 'anomaly_timeline' and 'results_path' in capture_info:
            results_df = pd.read_csv(capture_info['results_path'])
            combined_df = pd.merge(df, results_df, on='timestamp', how='left')
            viz_path = visualizer.plot_anomaly_timeline(combined_df, is_anomaly_col='is_anomaly',
                                                      score_col='anomaly_score', interactive=True)
        else:
            return jsonify({
                'success': False,
                'error': f"Visualization type '{viz_type}' not supported"
            }), 400
       
        if not viz_path or not os.path.exists(viz_path):
            return jsonify({
                'success': False,
                'error': f"Failed to generate visualization"
            }), 500
       
        # Return the visualization file
        return send_file(viz_path)
    except Exception as e:
        logger.error(f"Error generating visualization: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Create an initialization function to create directories and load models
def init_api():
    """Initialize the API by creating necessary directories and loading models."""
    # Create required directories
    for directory in [MODEL_DIR, DATA_DIR, RESULTS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
   
    # Load the latest model if available
    latest_model = get_latest_model()
    if latest_model:
        model_id = os.path.basename(latest_model)
        get_model(model_id)
        logger.info(f"Preloaded model: {model_id}")
   
    logger.info("API initialization completed")

# Call initialization function
init_api()

# Main function to run the API server
def main():
    """Main function to run the API server."""
    import argparse
   
    parser = argparse.ArgumentParser(description="Network Traffic Anomaly Detection API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to run API on")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Port to run API on")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
   
    args = parser.parse_args()
   
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()

