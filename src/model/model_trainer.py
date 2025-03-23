import os
import sys
import logging
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns

# Import custom modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.anomaly_detector import AnomalyDetector

class ModelTrainer:
    """
    Class for training and evaluating anomaly detection models.
    """
    def __init__(self, input_dir="../data/processed", output_dir="../data/models", results_dir="../data/results"):
        """
        Initialize ModelTrainer.
       
        Args:
            input_dir (str): Directory containing processed data
            output_dir (str): Directory to save trained models
            results_dir (str): Directory to save evaluation results
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.results_dir = results_dir
       
        # Create directories if they don't exist
        for directory in [output_dir, results_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
           
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
   
    def load_data(self, features_file=None, labels_file=None):
        """
        Load features and optional labels for training.
       
        Args:
            features_file (str): Path to features file (.npz or .csv)
            labels_file (str): Path to labels file (optional)
           
        Returns:
            tuple: (X_data, y_data) where y_data may be None if unlabeled
        """
        X_data = None
        y_data = None
       
        # Load features
        if not features_file:
            # Find most recent features file
            npz_files = [f for f in os.listdir(self.input_dir) if f.endswith('_features.npz')]
            csv_files = [f for f in os.listdir(self.input_dir) if f.endswith('_features.csv')]
           
            if npz_files:
                npz_files.sort(reverse=True)
                features_file = os.path.join(self.input_dir, npz_files[0])
            elif csv_files:
                csv_files.sort(reverse=True)
                features_file = os.path.join(self.input_dir, csv_files[0])
       
        if features_file:
            try:
                if features_file.endswith('.npz'):
                    self.logger.info(f"Loading features from {features_file}")
                    X_data = np.load(features_file)['X']
                elif features_file.endswith('.csv'):
                    self.logger.info(f"Loading features from {features_file}")
                    X_data = pd.read_csv(features_file).values
                else:
                    self.logger.error(f"Unsupported file format: {features_file}")
                    return None, None
               
                self.logger.info(f"Loaded features with shape {X_data.shape}")
            except Exception as e:
                self.logger.error(f"Error loading features: {str(e)}")
                return None, None
        else:
            self.logger.error("No features file found")
            return None, None
       
        # Load labels if provided
        if labels_file and os.path.exists(labels_file):
            try:
                self.logger.info(f"Loading labels from {labels_file}")
                if labels_file.endswith('.csv'):
                    df = pd.read_csv(labels_file)
                    if 'label' in df.columns:
                        y_data = df['label'].values
                    else:
                        y_data = df.iloc[:, 0].values  # Assume first column contains labels
                else:
                    y_data = np.load(labels_file)
               
                self.logger.info(f"Loaded {len(y_data)} labels")
            except Exception as e:
                self.logger.error(f"Error loading labels: {str(e)}")
       
        return X_data, y_data
   
    def train_model(self, X_train, model_type='isolation_forest', use_pca=True, pca_components=0.95):
        """
        Train an anomaly detection model.
       
        Args:
            X_train: Training data
            model_type (str): Type of anomaly detection model
            use_pca (bool): Whether to use PCA for dimensionality reduction
            pca_components: Number of PCA components or variance ratio to keep
           
        Returns:
            AnomalyDetector: Trained model
        """
        self.logger.info(f"Training {model_type} model on {X_train.shape[0]} samples")
       
        # Initialize and train model
        model = AnomalyDetector(model_type=model_type, model_dir=self.output_dir)
        model.fit(X_train, use_pca=use_pca, pca_components=pca_components)
       
        return model
   
    def evaluate_model(self, model, X_test, y_test=None):
        """
        Evaluate the trained model.
       
        Args:
            model: Trained anomaly detection model
            X_test: Test data
            y_test: Ground truth labels (optional)
           
        Returns:
            dict: Evaluation metrics
        """
        self.logger.info(f"Evaluating model on {X_test.shape[0]} samples")
       
        # Get predictions and anomaly scores
        predictions = model.predict(X_test)
        scores = model.decision_function(X_test)
       
        # Convert predictions to binary format (1 for normal, 0 for anomaly)
        binary_predictions = np.where(predictions > 0, 1, 0)
       
        # Calculate metrics if ground truth is available
        metrics = {}
        if y_test is not None:
            # Convert ground truth to binary format (1 for normal, 0 for anomaly)
            binary_truth = np.where(y_test > 0, 1, 0)
           
            metrics['accuracy'] = accuracy_score(binary_truth, binary_predictions)
            metrics['precision'] = precision_score(binary_truth, binary_predictions, zero_division=0)
            metrics['recall'] = recall_score(binary_truth, binary_predictions, zero_division=0)
            metrics['f1_score'] = f1_score(binary_truth, binary_predictions, zero_division=0)
           
            self.logger.info(f"Evaluation metrics: {metrics}")
       
        # Calculate anomaly distribution statistics
        anomaly_ratio = np.mean(binary_predictions == 0)
        metrics['anomaly_ratio'] = anomaly_ratio
        metrics['mean_score'] = np.mean(scores)
        metrics['min_score'] = np.min(scores)
        metrics['max_score'] = np.max(scores)
       
        self.logger.info(f"Anomaly ratio: {anomaly_ratio:.2%}")
       
        return metrics, predictions, scores
   
    def visualize_results(self, X_test, predictions, scores, output_file=None):
        """
        Visualize evaluation results.
       
        Args:
            X_test: Test data
            predictions: Model predictions
            scores: Anomaly scores
            output_file (str): Filename for output visualization
           
        Returns:
            str: Path to saved visualization file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_evaluation.png"
           
        output_path = os.path.join(self.results_dir, output_file)
       
        try:
            # Create a figure with multiple subplots
            plt.figure(figsize=(15, 10))
           
            # Plot 1: Score distribution
            plt.subplot(2, 2, 1)
            sns.histplot(scores, kde=True)
            plt.title('Anomaly Score Distribution')
            plt.xlabel('Anomaly Score')
            plt.ylabel('Frequency')
           
            # Plot 2: Score distribution by prediction
            plt.subplot(2, 2, 2)
            sns.boxplot(x=predictions, y=scores)
            plt.title('Anomaly Scores by Prediction')
            plt.xlabel('Prediction (1=Normal, -1=Anomaly)')
            plt.ylabel('Anomaly Score')
           
            # Plot 3: Try to project the data to 2D using PCA for visualization
            if X_test.shape[1] > 2:
                from sklearn.decomposition import PCA
                pca = PCA(n_components=2)
                X_2d = pca.fit_transform(X_test)
               
                plt.subplot(2, 2, 3)
                plt.scatter(X_2d[:, 0], X_2d[:, 1], c=predictions, cmap='viridis', alpha=0.5)
                plt.title('2D Projection of Data with Predictions')
                plt.xlabel('Principal Component 1')
                plt.ylabel('Principal Component 2')
                plt.colorbar(label='Prediction')
               
                # Plot 4: Same 2D projection but colored by anomaly score
                plt.subplot(2, 2, 4)
                sc = plt.scatter(X_2d[:, 0], X_2d[:, 1], c=scores, cmap='plasma', alpha=0.5)
                plt.title('2D Projection of Data with Anomaly Scores')
                plt.xlabel('Principal Component 1')
                plt.ylabel('Principal Component 2')
                plt.colorbar(sc, label='Anomaly Score')
           
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
           
            self.logger.info(f"Saved visualization to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing results: {str(e)}")
            return None
   
    def save_results(self, metrics, output_file=None):
        """
        Save evaluation metrics to file.
       
        Args:
            metrics (dict): Evaluation metrics
            output_file (str): Filename for output metrics
           
        Returns:
            str: Path to saved metrics file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            output_file = f"{timestamp}_metrics.csv"
           
        output_path = os.path.join(self.results_dir, output_file)
       
        try:
            # Convert metrics to DataFrame
            metrics_df = pd.DataFrame([metrics])
           
            # Save to CSV
            metrics_df.to_csv(output_path, index=False)
           
            self.logger.info(f"Saved metrics to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error saving metrics: {str(e)}")
            return None
   
    def run_training_pipeline(self, features_file=None, labels_file=None, model_type='isolation_forest',
                               test_size=0.2, use_pca=True, save_model=True):
        """
        Run the full training and evaluation pipeline.
       
        Args:
            features_file (str): Path to features file
            labels_file (str): Path to labels file (optional)
            model_type (str): Type of anomaly detection model
            test_size (float): Proportion of data to use for testing
            use_pca (bool): Whether to use PCA for dimensionality reduction
            save_model (bool): Whether to save the trained model
           
        Returns:
            tuple: (Trained model, evaluation metrics)
        """
        # Load data
        X_data, y_data = self.load_data(features_file, labels_file)
        if X_data is None:
            return None, None
       
        # Split data into train and test sets
        if y_data is not None:
            X_train, X_test, y_train, y_test = train_test_split(
                X_data, y_data, test_size=test_size, random_state=42
            )
        else:
            X_train, X_test = train_test_split(
                X_data, test_size=test_size, random_state=42
            )
            y_test = None
       
        # Train model
        model = self.train_model(X_train, model_type=model_type, use_pca=use_pca)
       
        # Save model if requested
        if save_model:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            model_file = f"{timestamp}_{model_type}_model.joblib"
            model.save_model(model_file)
       
        # Evaluate model
        metrics, predictions, scores = self.evaluate_model(model, X_test, y_test)
       
        # Visualize and save results
        self.visualize_results(X_test, predictions, scores)
        self.save_results(metrics)
       
        return model, metrics

def main():
    """
    Main function to run the model trainer.
    """
    parser = argparse.ArgumentParser(description="Anomaly Detection Model Trainer")
    parser.add_argument("--features", "-f", help="Path to features file")
    parser.add_argument("--labels", "-l", help="Path to labels file (optional)")
    parser.add_argument("--model-type", "-m", default="isolation_forest",
                        choices=["isolation_forest", "one_class_svm", "lof", "ensemble"],
                        help="Type of anomaly detection model")
    parser.add_argument("--test-size", "-t", type=float, default=0.2,
                        help="Proportion of data to use for testing")
    parser.add_argument("--no-pca", action="store_true", help="Disable PCA for dimensionality reduction")
   
    args = parser.parse_args()
   
    trainer = ModelTrainer()
    trainer.run_training_pipeline(
        features_file=args.features,
        labels_file=args.labels,
        model_type=args.model_type,
        test_size=args.test_size,
        use_pca=not args.no_pca
    )

if __name__ == "__main__":
    main()