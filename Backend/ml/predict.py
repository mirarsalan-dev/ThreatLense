import os
import joblib
import pandas as pd

class MLPredictor:
    def __init__(self):
        self.model = None
        self.feature_names = None
        
        # Determine absolute path to models
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(base_dir, 'model', 'rf_model.joblib')
        self.features_path = os.path.join(base_dir, 'model', 'model_features.joblib')
        
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.features_path):
                self.model = joblib.load(self.model_path)
                self.feature_names = joblib.load(self.features_path)
                print(f"Loaded ML model from {self.model_path}")
            else:
                print("Model files not found. Using fallback heuristics until model is trained.")
        except Exception as e:
            print(f"Error loading ML model: {e}")

    def predict(self, features_dict):
        """
        Returns prediction and confidence based on extracted features.
        """
        # Fallback if model isn't trained yet
        if self.model is None or self.feature_names is None:
            # Simple heuristic fallback
            risk = features_dict.get('qty_suspicious_words', 0) * 0.1
            if features_dict.get('is_https') == 0:
                risk += 0.2
            
            risk = min(risk, 0.99)
            return {
                "prediction": "phishing" if risk > 0.5 else "safe",
                "confidence": risk if risk > 0.5 else (1 - risk)
            }

        # Format features according to trained model expectations
        try:
            # Create a dataframe with a single row matching the expected feature columns
            df_features = pd.DataFrame([features_dict])
            
            # Ensure columns are in the exact same order as training
            # Missing columns get 0, extra columns are dropped
            for col in self.feature_names:
                if col not in df_features.columns:
                    df_features[col] = 0
                    
            df_features = df_features[self.feature_names]
            
            prediction = self.model.predict(df_features)[0]
            probabilities = self.model.predict_proba(df_features)[0]
            confidence = probabilities[1] if prediction == 1 else probabilities[0]
            
            # XAI: Explainable AI - Extract contributing features
            explanations = []
            if hasattr(self.model, 'feature_importances_'):
                for i, col in enumerate(self.feature_names):
                    val = df_features[col].iloc[0]
                    imp = self.model.feature_importances_[i]
                    if imp > 0.01: # Only care about features that matter to the model globally
                        explanations.append({
                            "feature": col,
                            "value": float(val),
                            "importance": float(imp),
                            "description": f"Model gives {imp*100:.1f}% global importance to this feature."
                        })
                # Sort by importance and take top 5
                explanations = sorted(explanations, key=lambda x: x['importance'], reverse=True)[:5]
            
            return {
                "prediction": "phishing" if prediction == 1 else "safe",
                "confidence": float(confidence),
                "explanations": explanations
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                "prediction": "unknown",
                "confidence": 0.0
            }
