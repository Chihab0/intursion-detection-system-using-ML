# detection/engine.py
import os
import joblib
import pandas as pd
from features.feature_extractor import extract_features
from features.flow_builder import build_flows

# Paths to ML artifacts
MODEL_PATH = os.path.join("ml", "xgboost_ids_model_top20.pkl")
SCALER_PATH = os.path.join("ml", "scaler.pkl")

class DetectionEngine:
    def __init__(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        """
        Load the trained XGBoost model and the scaler.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")

        print("🔹 Loading XGBoost model...")
        self.model = joblib.load(model_path)
        print("✅ Model loaded.")

        print("🔹 Loading scaler...")
        self.scaler = joblib.load(scaler_path)
        print("✅ Scaler loaded.")

        # Only include classes used during training
        self.label_mapping = {
            0: "BENIGN",
            1: "DDoS",
            2: "PortScan",
            3: "BruteForce",
            4: "DoS"
        }

    def preprocess_flows(self, flows_dict) -> pd.DataFrame:
        """
        Extract features from flows and scale them for prediction.
        """
        features_df = extract_features(flows_dict)
        if features_df.empty:
            return pd.DataFrame(), pd.DataFrame()

        # Ensure all features used in training are present
        feature_columns = self.model.feature_names_in_
        for col in feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0

        X = features_df[feature_columns].fillna(0)
        X_scaled = self.scaler.transform(X)
        return X_scaled, features_df

    def predict_flows(self, flows_dict):
        """
        Predict labels for multiple flows.
        Returns a DataFrame with features + 'ML_Label'.
        """
        X_scaled, features_df = self.preprocess_flows(flows_dict)
        if features_df.empty:
            features_df['ML_Label'] = []
            return features_df

        preds = self.model.predict(X_scaled)
        features_df['ML_Label'] = [self.label_mapping.get(p, "Unknown") for p in preds]
        return features_df

    def predict_single_flow(self, pkt_list):
        """
        Predict a single flow given a list of packets.
        """
        flows = build_flows(pkt_list)
        df = self.predict_flows(flows)
        if df.empty:
            return "Unknown"
        return df['ML_Label'].iloc[0]

    def log_results(self, df: pd.DataFrame, log_path='logs/detection_log.csv'):
        """
        Save detection results to CSV.
        """
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        df.to_csv(log_path, index=False)
        print(f"✅ Detection results logged to {log_path}")

