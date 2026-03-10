# =====================================================
# CREATE ENSEMBLE MODEL
# Combines XGBoost and CatBoost into a single ensemble model
# with weighted voting (more weight to CatBoost)
# =====================================================

import joblib
import numpy as np
from catboost import CatBoostClassifier
import xgboost as xgb

# =====================================================
# ENSEMBLE MODEL CLASS
# =====================================================

class WeightedEnsembleModel:
    """
    Ensemble model that combines XGBoost and CatBoost predictions
    with weighted voting. CatBoost gets more weight.
    """
    
    def __init__(self, xgboost_model, catboost_model, catboost_weight=0.7, xgboost_weight=0.3):
        """
        Initialize ensemble model
        
        Args:
            xgboost_model: Trained XGBoost model
            catboost_model: Trained CatBoost model
            catboost_weight: Weight for CatBoost predictions (default: 0.7)
            xgboost_weight: Weight for XGBoost predictions (default: 0.3)
        """
        self.xgboost_model = xgboost_model
        self.catboost_model = catboost_model
        self.catboost_weight = catboost_weight
        self.xgboost_weight = xgboost_weight
        
        # Normalize weights to ensure they sum to 1
        total_weight = catboost_weight + xgboost_weight
        self.catboost_weight = catboost_weight / total_weight
        self.xgboost_weight = xgboost_weight / total_weight
    
    def predict(self, X):
        """
        Make predictions using weighted voting
        
        Args:
            X: Input features (scaled)
            
        Returns:
            Predicted labels
        """
        # If XGBoost weight is 0, use only CatBoost
        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict(X)
        
        # Get probabilities from both models
        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)
        
        # Weighted average of probabilities
        ensemble_proba = (
            self.catboost_weight * catboost_proba + 
            self.xgboost_weight * xgboost_proba
        )
        
        # Get final prediction from weighted probabilities
        ensemble_pred = np.argmax(ensemble_proba, axis=1)
        
        return ensemble_pred
    
    def predict_proba(self, X):
        """
        Get prediction probabilities using weighted voting
        
        Args:
            X: Input features (scaled)
            
        Returns:
            Prediction probabilities
        """
        # If XGBoost weight is 0, use only CatBoost
        if self.xgboost_weight == 0.0:
            return self.catboost_model.predict_proba(X)
        
        # Get probabilities from both models
        catboost_proba = self.catboost_model.predict_proba(X)
        xgboost_proba = self.xgboost_model.predict_proba(X)
        
        # Weighted average of probabilities
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
# LOAD INDIVIDUAL MODELS AND CREATE ENSEMBLE
# =====================================================

print("="*60)
print("🔧 CREATING ENSEMBLE MODEL")
print("="*60)
print()

# Load XGBoost model
print("📦 Loading XGBoost model...")
try:
    xgboost_model = joblib.load("xgboost_model.pkl")
    print("✅ XGBoost model loaded successfully")
except FileNotFoundError:
    print("❌ Error: xgboost_model.pkl not found!")
    print("   Please ensure xgboost_model.pkl exists in the current directory.")
    raise
except Exception as e:
    print(f"❌ Error loading XGBoost model: {e}")
    raise

# Load CatBoost model
print("📦 Loading CatBoost model...")
try:
    catboost_model = CatBoostClassifier()
    catboost_model.load_model("catboost_model.cbm")
    print("✅ CatBoost model loaded successfully")
except FileNotFoundError:
    print("❌ Error: catboost_model.cbm not found!")
    print("   Please ensure catboost_model.cbm exists in the current directory.")
    raise
except Exception as e:
    print(f"❌ Error loading CatBoost model: {e}")
    raise

# Create ensemble with weighted voting
# CatBoost gets 100% weight, XGBoost gets 0% weight (CatBoost only)
print("\n🔗 Creating ensemble model...")
print("   CatBoost weight: 1.0 (100%)")
print("   XGBoost weight: 0.0 (0%)")

ensemble_model = WeightedEnsembleModel(
    xgboost_model=xgboost_model,
    catboost_model=catboost_model,
    catboost_weight=1.0,  # Full weight to CatBoost only
    xgboost_weight=0.0     # No weight to XGBoost
)

# Display ensemble info
info = ensemble_model.get_model_info()
print(f"\n📊 Ensemble Model Info:")
print(f"   CatBoost weight: {info['catboost_weight']:.2%}")
print(f"   XGBoost weight: {info['xgboost_weight']:.2%}")
print(f"   Total models: {info['total_models']}")

# Save ensemble model as a single file
print("\n💾 Saving ensemble model...")
try:
    joblib.dump(ensemble_model, "ensemble_model.pkl")
    print("✅ Ensemble model saved as 'ensemble_model.pkl'")
    print("\n📁 You can now use 'ensemble_model.pkl' without needing")
    print("   the individual XGBoost and CatBoost model files!")
    print("\n💡 To use the ensemble model:")
    print("   import joblib")
    print("   model = joblib.load('ensemble_model.pkl')")
    print("   predictions = model.predict(X_scaled)")
    print("   probabilities = model.predict_proba(X_scaled)")
except Exception as e:
    print(f"❌ Error saving ensemble model: {e}")
    raise

print("\n" + "="*60)
print("✅ ENSEMBLE MODEL CREATION COMPLETE")
print("="*60)
print("\n📝 The ensemble model is now saved as 'ensemble_model.pkl'")
print("   You can export this single file to other directories.")
print("   Make sure the target environment has 'xgboost' and 'catboost' installed.")
print()
