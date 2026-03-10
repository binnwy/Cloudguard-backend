# =====================================================
# PREDICTION USING ENSEMBLE MODEL
# Tests the ensemble model with DoS and BruteForce attack samples
# =====================================================

import pandas as pd
import numpy as np
import joblib

# ---------------- LABEL MAPPING ----------------
LABEL_MAP = {
    0: "Benign",
    1: "DoS",
    2: "DDoS",
    3: "PortScan",
    4: "BruteForce",
    5: "WebAttack"
}

# ---------------- ENSEMBLE MODEL CLASS ----------------
# (Required for loading the saved ensemble model)

class WeightedEnsembleModel:
    """
    Ensemble model that combines XGBoost and CatBoost predictions
    with weighted voting. CatBoost gets more weight.
    """
    
    def __init__(self, xgboost_model, catboost_model, catboost_weight=0.7, xgboost_weight=0.3):
        self.xgboost_model = xgboost_model
        self.catboost_model = catboost_model
        self.catboost_weight = catboost_weight
        self.xgboost_weight = xgboost_weight
        
        # Normalize weights to ensure they sum to 1
        total_weight = catboost_weight + xgboost_weight
        self.catboost_weight = catboost_weight / total_weight
        self.xgboost_weight = xgboost_weight / total_weight
    
    def predict(self, X):
        """Make predictions using weighted voting"""
        # If XGBoost weight is 0, use only CatBoost
        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict(X)
        
        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)
        
        ensemble_proba = (
            self.catboost_weight * catboost_proba + 
            self.xgboost_weight * xgboost_proba
        )
        
        ensemble_pred = np.argmax(ensemble_proba, axis=1)
        return ensemble_pred
    
    def predict_proba(self, X):
        """Get prediction probabilities using weighted voting"""
        # If XGBoost weight is 0, use only CatBoost
        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict_proba(X)
        
        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)
        
        ensemble_proba = (
            self.catboost_weight * catboost_proba + 
            self.xgboost_weight * xgboost_proba
        )
        
        return ensemble_proba
    
    def get_model_info(self):
        """Get information about the ensemble model"""
        return {
            "catboost_weight": self.catboost_weight,
            "xgboost_weight": self.xgboost_weight,
            "total_models": 2
        }

# =====================================================
# LOAD ENSEMBLE MODEL
# =====================================================

print("="*60)
print("ENSEMBLE MODEL PREDICTIONS")
print("="*60)
print()

print("Loading ensemble model...")
try:
    model = joblib.load("ensemble_model.pkl")
    print("SUCCESS: Ensemble model loaded successfully\n")
except FileNotFoundError:
    print("ERROR: ensemble_model.pkl not found!")
    print("   Please run 'create_ensemble_model.py' first to create the ensemble model.")
    exit(1)
except Exception as e:
    print(f"ERROR: Error loading ensemble model: {e}")
    exit(1)

# =====================================================
# ATTACK SAMPLES (ALREADY SCALED)
# =====================================================

# BruteForce attack sample
bf_attack_sample = pd.DataFrame([{
    "Dst Port": 0.477214,
    "Protocol": 0.955075,
    "Flow Duration": 0.115259,
    "Tot Fwd Pkts": -0.006775,
    "TotLen Fwd Pkts": 0.332535,
    "Flow Byts/s": 0.966205,
    "Flow Pkts/s": 1.063181,
    "Pkt Size Avg": -0.434789
}])

# DoS attack sample
dos_attack_sample = pd.DataFrame([{
    "Dst Port": 0.132751,
    "Protocol": -0.435226,
    "Flow Duration": -0.011893,
    "Tot Fwd Pkts": -0.018265,
    "TotLen Fwd Pkts": -0.014035,
    "Flow Byts/s": -0.049256,
    "Flow Pkts/s": -0.273198,
    "Pkt Size Avg": -0.072536
}])

# =====================================================
# PREDICTION FUNCTION
# =====================================================

def predict_and_display(sample, sample_name):
    """
    Make predictions using ensemble model and display results
    
    Args:
        sample: DataFrame with scaled features
        sample_name: Name of the attack sample
    """
    print("="*60)
    print(f"PREDICTING: {sample_name}")
    print("="*60)
    print()
    
    # Prepare input (ensure correct column order)
    X = sample[[
        "Dst Port",
        "Protocol",
        "Flow Duration",
        "Tot Fwd Pkts",
        "TotLen Fwd Pkts",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Pkt Size Avg"
    ]]
    
    # Get predictions
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    
    # Extract results
    if isinstance(predictions, np.ndarray):
        predicted_label = int(predictions.item() if predictions.size == 1 else predictions[0])
    else:
        predicted_label = int(predictions[0])
    
    # Handle probabilities array
    if len(probabilities.shape) > 1:
        prob_array = probabilities[0]
    else:
        prob_array = probabilities
    
    confidence = float(np.max(prob_array))
    attack_type = LABEL_MAP.get(predicted_label, f"Unknown({predicted_label})")
    
    # Display results
    print(f"Prediction Results:")
    print(f"   Attack Type: {attack_type}")
    print(f"   Predicted Label: {predicted_label}")
    print(f"   Confidence: {confidence:.4f} ({confidence*100:.2f}%)")
    print()
    print(f"Probability Distribution:")
    for i, prob in enumerate(prob_array):
        label_name = LABEL_MAP.get(i, f"Unknown({i})")
        bar_length = int(prob * 50)  # Scale to 50 chars max
        bar = "#" * bar_length
        print(f"   {label_name:15s}: {prob:.4f} ({prob*100:6.2f}%) {bar}")
    print()
    
    # Display input features
    print(f"Input Features (Scaled):")
    for col in X.columns:
        print(f"   {col:20s}: {X[col].iloc[0]:.6f}")
    print()
    
    return {
        "attack_type": attack_type,
        "predicted_label": predicted_label,
        "confidence": confidence,
        "probabilities": prob_array
    }

# =====================================================
# RUN PREDICTIONS
# =====================================================

# Predict BruteForce attack
bf_results = predict_and_display(bf_attack_sample, "BRUTE FORCE ATTACK")

# Predict DoS attack
dos_results = predict_and_display(dos_attack_sample, "DoS ATTACK")

# =====================================================
# SUMMARY
# =====================================================

print("="*60)
print("PREDICTION SUMMARY")
print("="*60)
print()
print(f"1. BruteForce Attack Sample:")
print(f"   -> Predicted as: {bf_results['attack_type']}")
print(f"   -> Confidence: {bf_results['confidence']*100:.2f}%")
print()
print(f"2. DoS Attack Sample:")
print(f"   -> Predicted as: {dos_results['attack_type']}")
print(f"   -> Confidence: {dos_results['confidence']*100:.2f}%")
print()
print("="*60)
print("PREDICTIONS COMPLETE")
print("="*60)
