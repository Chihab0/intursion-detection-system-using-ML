# ml/predict.py
import pandas as pd
from ml.model_loader import load_model_and_scaler
from features.feature_extractor import extract_features

# Only the top 20 features used during training
TOP_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'Fwd Header Length', 'Bwd Header Length',
    'Average Packet Size', 'Subflow Fwd Bytes'
]

# Correct label mapping (matches trained model)
LABEL_MAPPING = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "BruteForce",
    4: "DoS"
}

# Load model and scaler once
model, scaler = load_model_and_scaler()

def predict_flows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Predict multiple flows from a DataFrame of raw flows.
    Adds a column 'ML_Label' with predictions.
    """
    if df.empty:
        df['ML_Label'] = []
        return df

    # Extract features
    features_df = extract_features(df)

    # Keep only the features used during training
    X = features_df[TOP_FEATURES].fillna(0)

    # Scale features
    X_scaled = scaler.transform(X)

    # Predict
    preds = model.predict(X_scaled)
    df['ML_Label'] = [LABEL_MAPPING.get(p, "Unknown") for p in preds]
    return df

def predict_single_flow(flow: dict) -> str:
    """
    Predict a single flow given as a dictionary of raw attributes.
    """
    df = pd.DataFrame([flow])
    result_df = predict_flows(df)
    return result_df['ML_Label'].iloc[0]

