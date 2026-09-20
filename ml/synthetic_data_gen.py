import pandas as pd
import numpy as np
import random
import os

from feature_extractor import FeatureExtractor

def generate_synthetic_data(num_samples=1000):
    """
    Generates a synthetic dataset of URL features for ML training.
    """
    print(f"Generating {num_samples} synthetic URL samples...")
    
    benign_domains = ['google.com', 'github.com', 'microsoft.com', 'wikipedia.org', 'apple.com']
    phishing_domains = ['secure-login-update-account.com', 'verify-paypal-now.net', 'free-gift-cards.info', '192.168.1.100']
    
    extractor = FeatureExtractor()
    data = []
    
    for i in range(num_samples):
        is_phishing = random.choice([0, 1])
        
        if is_phishing:
            domain = random.choice(phishing_domains)
            path = f"/login/secure/{random.randint(1000, 9999)}/update"
            query = "?token=" + "a" * random.randint(10, 50)
            url = f"http://{domain}{path}{query}"
        else:
            domain = random.choice(benign_domains)
            path = "/about/contact" if random.choice([True, False]) else ""
            query = "?q=search" if random.choice([True, False]) else ""
            url = f"https://{domain}{path}{query}"
            
        features = extractor.extract_features(url)
        features['label'] = is_phishing
        data.append(features)
        
    df = pd.DataFrame(data)
    
    # Save to CSV
    os.makedirs('dataset', exist_ok=True)
    csv_path = os.path.join('dataset', 'synthetic_urls.csv')
    df.to_csv(csv_path, index=False)
    print(f"Dataset generated and saved to {csv_path}")

if __name__ == "__main__":
    generate_synthetic_data(2000)
