# detection/engine.py
import os
import joblib
import pandas as pd
from features.feature_extractor import extract_features
from features.flow_builder import build_flows

# Paths to ML artifacts
MODEL_PATH = os.path.join("ml", "xgboost_ids_model.pkl")
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

        # Exact training feature order
        self.expected_features = [
            'Destination Port',
            'Flow Duration',
            'Total Fwd Packets',
            'Total Backward Packets',
            'Total Length of Fwd Packets',
            'Total Length of Bwd Packets',
            'Fwd Packet Length Max',
            'Fwd Packet Length Min',
            'Fwd Packet Length Mean',
            'Bwd Packet Length Max',
            'Bwd Packet Length Min',
            'Bwd Packet Length Mean',
            'Flow Bytes/s',
            'Flow Packets/s',
            'Fwd IAT Mean',
            'Bwd IAT Mean',
            'Fwd Header Length',
            'Bwd Header Length',
            'Average Packet Size',
            'Subflow Fwd Bytes'
        ]

    def _identify_portscan_sources(self, df: pd.DataFrame):
        """Identify likely scanning source IPs via aggregation heuristics."""
        required_cols = {'Src IP', 'Destination Port', 'Total Backward Packets', 'Flow Duration'}
        if not required_cols.issubset(df.columns):
            return set()
        suspects = set()
        grp = df.groupby('Src IP', dropna=True)
        for src, g in grp:
            if g.empty:
                continue
            n_flows = len(g)
            unique_ports = g['Destination Port'].nunique(dropna=True)
            low_bwd_ratio = (g['Total Backward Packets'] <= 1).mean()  # mostly no responses
            short_dur_ratio = (g['Flow Duration'] <= 0.02).mean()       # bursts of very short flows
            # Dynamic thresholds scale with number of flows
            port_thresh = max(20, int(0.2 * n_flows))
            if unique_ports >= port_thresh and low_bwd_ratio >= 0.8 and short_dur_ratio >= 0.8:
                suspects.add(src)
        return suspects

    def _identify_ddos_targets(self, df: pd.DataFrame):
        """Identify likely DDoS targets via aggregation heuristics across flows."""
        required_cols = {'Src IP', 'Dst IP', 'Destination Port', 'Total Backward Packets', 'Flow Duration'}
        if not required_cols.issubset(df.columns):
            return set()
        targets = set()
        grp = df.groupby(['Dst IP', 'Destination Port'], dropna=True)
        for (dst_ip, dport), g in grp:
            if g.empty:
                continue
            n_flows = len(g)
            unique_src = g['Src IP'].nunique(dropna=True)
            low_bwd_ratio = (g['Total Backward Packets'] <= 1).mean()
            avg_dur = g['Flow Duration'].mean()
            # Dynamic thresholds
            flows_thresh = max(50, int(0.25 * len(df)))
            unique_src_thresh = max(20, int(0.2 * n_flows))
            if n_flows >= flows_thresh and unique_src >= unique_src_thresh and low_bwd_ratio >= 0.95 and avg_dur <= 0.1:
                targets.add((dst_ip, dport))
        return targets

    def preprocess_flows(self, flows_dict) -> pd.DataFrame:
        """
        Extract features from flows and scale them for prediction.
        """
        features_df = extract_features(flows_dict)
        if features_df.empty:
            return pd.DataFrame(), pd.DataFrame()

        # Ensure all features used in training are present
        for col in self.expected_features:
            if col not in features_df.columns:
                features_df[col] = 0

        X = features_df[self.expected_features].fillna(0)
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
        features_df['ML_Label'] = [self.label_mapping.get(int(p), "Unknown") for p in preds]

        # Apply PortScan heuristic override (per source fan-out)
        scan_sources = self._identify_portscan_sources(features_df)
        if scan_sources:
            mask = features_df['Src IP'].isin(scan_sources)
            features_df.loc[mask, 'ML_Label'] = 'PortScan'

        # Apply DDoS heuristic override (per target fan-in)
        ddos_targets = self._identify_ddos_targets(features_df)
        if ddos_targets:
            mask_ddos = features_df.apply(lambda r: (r.get('Dst IP'), r.get('Destination Port')) in ddos_targets, axis=1)
            features_df.loc[mask_ddos, 'ML_Label'] = 'DDoS'
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

