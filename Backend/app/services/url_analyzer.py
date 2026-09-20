import os
import sys

# Ensure ml directory is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from ml.feature_extractor import FeatureExtractor
from ml.predict import MLPredictor

class URLAnalyzerService:
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.predictor = MLPredictor()

    def analyze_url(self, url):
        """
        Extracts features and predicts if URL is phishing.
        """
        # 1. Feature Extraction
        features = self.extractor.extract_features(url)
        
        # 2. ML Prediction
        ml_result = self.predictor.predict(features)
        
        # 3. Compile report
        return {
            "url": url,
            "features": features,
            "ml_analysis": ml_result
        }
