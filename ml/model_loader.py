# ml/model_loader.py
import os
import joblib

# Paths to ML artifacts
MODEL_PATH = os.path.join("ml", "xgboost_ids_model.pkl")
SCALER_PATH = os.path.join("ml", "scaler.pkl")


def load_model_and_scaler(model_path=MODEL_PATH, scaler_path=SCALER_PATH):
    """
    Load the trained XGBoost model and the StandardScaler.
    Returns: model, scaler
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler file not found: {scaler_path}")

    print("🔹 Loading XGBoost model...")
    model = joblib.load(model_path)
    print("✅ Model loaded.")

    print("🔹 Loading scaler...")
    scaler = joblib.load(scaler_path)
    print("✅ Scaler loaded.")

    return model, scaler

