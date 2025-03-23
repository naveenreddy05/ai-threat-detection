# New file: src/model/deep_anomaly_detector.py
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import LSTM, Dense, Input, Dropout, RepeatVector, TimeDistributed

class DeepAnomalyDetector:
    """Deep learning-based anomaly detection using LSTMs or Autoencoders."""
   
    def __init__(self, model_type='lstm_autoencoder', sequence_length=10, model_dir="../data/models"):
        self.model_type = model_type
        self.sequence_length = sequence_length
        self.model_dir = model_dir
        self.model = None
        self.feature_scaler = None
       
    def _build_lstm_autoencoder(self, input_shape, encoding_dim=8):
        """Build an LSTM autoencoder model for sequence anomaly detection."""
        # Encoder
        inputs = Input(shape=input_shape)
        encoded = LSTM(encoding_dim*2, return_sequences=False)(inputs)
        encoded = Dropout(0.2)(encoded)
        encoded = Dense(encoding_dim, activation='relu')(encoded)
       
        # Decoder
        decoded = RepeatVector(input_shape[0])(encoded)
        decoded = LSTM(encoding_dim*2, return_sequences=True)(decoded)
        decoded = TimeDistributed(Dense(input_shape[1]))(decoded)
       
        # Autoencoder model
        autoencoder = Model(inputs, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
       
        # Encoder model for feature extraction
        encoder = Model(inputs, encoded)
       
        return autoencoder, encoder
   
    def fit(self, X, sequence_data=None, epochs=50, batch_size=32, validation_split=0.1):
        """Train the deep anomaly detection model."""
        from sklearn.preprocessing import StandardScaler
        import numpy as np
       
        # Prepare data for sequence models
        if self.model_type.startswith('lstm') and sequence_data is None:
            # Convert to sequences if not provided
            self.feature_scaler = StandardScaler()
            X_scaled = self.feature_scaler.fit_transform(X)
           
            # Create sequences from the data
            sequences = []
            for i in range(len(X_scaled) - self.sequence_length + 1):
                sequences.append(X_scaled[i:i+self.sequence_length])
           
            sequence_data = np.array(sequences)
        elif not self.model_type.startswith('lstm'):
            # For non-sequence models
            self.feature_scaler = StandardScaler()
            X_scaled = self.feature_scaler.fit_transform(X)
            sequence_data = X_scaled
       
        # Build the appropriate model
        if self.model_type == 'lstm_autoencoder':
            input_shape = (self.sequence_length, X.shape[1])
            self.model, self.encoder = self._build_lstm_autoencoder(input_shape)
        else:
            # Implement other deep learning models here
            raise ValueError(f"Unsupported model type: {self.model_type}")
       
        # Train the model
        history = self.model.fit(
            sequence_data, sequence_data,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            shuffle=True
        )
       
        # Calculate reconstruction error threshold for anomaly detection
        predictions = self.model.predict(sequence_data)
        mse = np.mean(np.power(sequence_data - predictions, 2), axis=(1, 2))
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
       
        return history
   
    def predict(self, X):
        """Predict anomalies in the data."""
        import numpy as np
       
        # Prepare data for prediction
        if self.model_type.startswith('lstm'):
            X_scaled = self.feature_scaler.transform(X)
           
            # Create sequences
            sequences = []
            for i in range(len(X_scaled) - self.sequence_length + 1):
                sequences.append(X_scaled[i:i+self.sequence_length])
           
            test_sequences = np.array(sequences)
           
            # Make predictions
            predictions = self.model.predict(test_sequences)
           
            # Calculate reconstruction error
            mse = np.mean(np.power(test_sequences - predictions, 2), axis=(1, 2))
           
            # Convert to anomaly score and prediction (-1 for anomaly, 1 for normal)
            predictions = np.ones(len(X))
            predictions[-len(mse):] = np.where(mse > self.threshold, -1, 1)
           
            return predictions
        else:
            # For non-sequence models
            X_scaled = self.feature_scaler.transform(X)
            predictions = self.model.predict(X_scaled)
            return predictions
   
    def decision_function(self, X):
        """Get anomaly scores for the data."""
        import numpy as np
       
        # Prepare data for prediction
        if self.model_type.startswith('lstm'):
            X_scaled = self.feature_scaler.transform(X)
           
            # Create sequences
            sequences = []
            for i in range(len(X_scaled) - self.sequence_length + 1):
                sequences.append(X_scaled[i:i+self.sequence_length])
           
            test_sequences = np.array(sequences)
           
            # Make predictions
            predictions = self.model.predict(test_sequences)
           
            # Calculate reconstruction error
            mse = np.mean(np.power(test_sequences - predictions, 2), axis=(1, 2))
           
            # Convert to scores (negative for consistency with other models)
            scores = np.zeros(len(X))
            scores[-len(mse):] = -mse  # Negative MSE as score
           
            return scores
        else:
            # For non-sequence models
            X_scaled = self.feature_scaler.transform(X)
            return -self.model.predict(X_scaled)
   
    # Add save and load functions similar to the existing AnomalyDetector class