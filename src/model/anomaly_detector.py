# src/model/anomaly_detector.py
import os
import logging
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

class AnomalyDetector:
    """
    Class for detecting anomalies in network traffic data using various algorithms.
    """
    def __init__(self, model_type='isolation_forest', model_dir="../data/models"):
        """
        Initialize AnomalyDetector.
       
        Args:
            model_type (str): Type of anomaly detection model
                              ('isolation_forest', 'one_class_svm', 'lof', 'ensemble')
            model_dir (str): Directory to save/load models
        """
        self.model_type = model_type
        self.model_dir = model_dir
        self.model = None
        self.pca = None
        self.scaler = None
       
        # Create model directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
           
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
       
        # Initialize model based on type
        self._initialize_model()
   
    @staticmethod
    def _create_model(model_type, contamination='auto'):
        """Create a model with the specified parameters."""
        if model_type == 'isolation_forest':
            from sklearn.ensemble import IsolationForest
            return IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=contamination,
                random_state=42,
                n_jobs=-1
            )
        elif model_type == 'one_class_svm':
            from sklearn.svm import OneClassSVM
            nu = 0.01 if contamination == 'auto' else contamination
            return OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=nu
            )
        elif model_type == 'lof':
            from sklearn.neighbors import LocalOutlierFactor
            return LocalOutlierFactor(
                n_neighbors=20,
                contamination=contamination,
                novelty=True
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
       
    def _initialize_model(self):
        """Initialize the anomaly detection model based on the specified type."""
        if self.model_type == 'ensemble':
            self.models = {
                'isolation_forest': self._create_model('isolation_forest'),
                'one_class_svm': self._create_model('one_class_svm'),
                'lof': self._create_model('lof')
            }
        else:
            self.model = self._create_model(self.model_type)
   
    def fit(self, X, use_pca=True, pca_components=0.95):
        """
        Train the anomaly detection model.
       
        Args:
            X: Input features (numpy array or DataFrame)
            use_pca (bool): Whether to use PCA for dimensionality reduction
            pca_components: Number of PCA components or variance ratio to keep
           
        Returns:
            self: Trained model
        """
        # Convert DataFrame to numpy array if needed
        if isinstance(X, pd.DataFrame):
            X = X.values
           
        self.logger.info(f"Training {self.model_type} model on data with shape {X.shape}")
       
        # Apply scaling
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
       
        # Apply PCA if requested
        if use_pca:
            self.pca = PCA(n_components=pca_components)
            X_transformed = self.pca.fit_transform(X_scaled)
            self.logger.info(f"Reduced dimensions from {X.shape[1]} to {X_transformed.shape[1]} using PCA")
        else:
            X_transformed = X_scaled
           
        # Train the model
        if self.model_type == 'ensemble':
            for name, model in self.models.items():
                self.logger.info(f"Training ensemble component: {name}")
                model.fit(X_transformed)
        else:
            self.model.fit(X_transformed)
           
        self.logger.info(f"Successfully trained {self.model_type} model")
        return self
   
    def predict(self, X):
        """
        Predict anomalies in the data.
       
        Args:
            X: Input features (numpy array or DataFrame)
           
        Returns:
            numpy.ndarray: Anomaly predictions (1 for normal, -1 for anomaly)
        """
        # Convert DataFrame to numpy array if needed
        if isinstance(X, pd.DataFrame):
            X = X.values
           
        # Apply scaling
        X_scaled = self.scaler.transform(X)
       
        # Apply PCA if it was used during training
        if self.pca is not None:
            X_transformed = self.pca.transform(X_scaled)
        else:
            X_transformed = X_scaled
           
        # Make predictions
        if self.model_type == 'ensemble':
            # Combine predictions from all models (majority voting)
            predictions = np.zeros((X_transformed.shape[0], len(self.models)))
            for i, (name, model) in enumerate(self.models.items()):
                predictions[:, i] = model.predict(X_transformed)
           
            # Final prediction: anomaly if majority of models predict anomaly
            final_predictions = np.sign(np.sum(predictions, axis=1))
            return final_predictions
        else:
            return self.model.predict(X_transformed)
   
    def decision_function(self, X):
        """
        Get anomaly scores for the data.
       
        Args:
            X: Input features (numpy array or DataFrame)
           
        Returns:
            numpy.ndarray: Anomaly scores (lower values indicate more anomalous points)
        """
        # Convert DataFrame to numpy array if needed
        if isinstance(X, pd.DataFrame):
            X = X.values
           
        # Apply scaling
        X_scaled = self.scaler.transform(X)
       
        # Apply PCA if it was used during training
        if self.pca is not None:
            X_transformed = self.pca.transform(X_scaled)
        else:
            X_transformed = X_scaled
           
        # Get anomaly scores
        if self.model_type == 'ensemble':
            # Average scores from all models
            scores = np.zeros((X_transformed.shape[0], len(self.models)))
            for i, (name, model) in enumerate(self.models.items()):
                if hasattr(model, 'decision_function'):
                    scores[:, i] = model.decision_function(X_transformed)
                elif hasattr(model, 'score_samples'):
                    scores[:, i] = model.score_samples(X_transformed)
                else:
                    scores[:, i] = 0
           
            # Return average score
            return np.mean(scores, axis=1)
        else:
            if hasattr(self.model, 'decision_function'):
                return self.model.decision_function(X_transformed)
            elif hasattr(self.model, 'score_samples'):
                return self.model.score_samples(X_transformed)
            else:
                return np.zeros(X_transformed.shape[0])
   
    def save_model(self, filename=None):
        """
        Save trained model to disk.
       
        Args:
            filename (str): Filename for saved model (default: based on model type)
           
        Returns:
            str: Path to saved model
        """
        if filename is None:
            filename = f"{self.model_type}_anomaly_detector.joblib"
           
        model_path = os.path.join(self.model_dir, filename)
       
        # Save model and preprocessing components
        model_data = {
            'model_type': self.model_type,
            'pca': self.pca,
            'scaler': self.scaler
        }
       
        if self.model_type == 'ensemble':
            model_data['models'] = self.models
        else:
            model_data['model'] = self.model
           
        try:
            joblib.dump(model_data, model_path)
            self.logger.info(f"Saved model to {model_path}")
            return model_path
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            return None
   
    def load_model(self, filename=None):
        """
        Load trained model from disk.
       
        Args:
            filename (str): Filename for saved model (default: based on model type)
           
        Returns:
            self: Loaded model
        """
        if filename is None:
            filename = f"{self.model_type}_anomaly_detector.joblib"
           
        model_path = os.path.join(self.model_dir, filename) if not os.path.isabs(filename) else filename
       
        try:
            if not os.path.exists(model_path):
                self.logger.error(f"Model file not found: {model_path}")
                return None
               
            model_data = joblib.load(model_path)
           
            # Load model and preprocessing components
            self.model_type = model_data['model_type']
            self.pca = model_data['pca']
            self.scaler = model_data['scaler']
           
            if self.model_type == 'ensemble':
                self.models = model_data['models']
            else:
                self.model = model_data['model']
               
            self.logger.info(f"Loaded model from {model_path}")
            return self
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return None
