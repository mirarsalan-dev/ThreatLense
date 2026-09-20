import pandas as pd
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from synthetic_data_gen import generate_synthetic_data

def train_model():
    dataset_path = os.path.join('dataset', 'synthetic_urls.csv')
    
    if not os.path.exists(dataset_path):
        print("Dataset not found. Generating synthetic data...")
        generate_synthetic_data(2000)
        
    print("Loading dataset...")
    df = pd.DataFrame(pd.read_csv(dataset_path))
    
    # Separate features and target
    X = df.drop('label', axis=1)
    y = df['label']
    
    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1-Score:  {f1_score(y_test, y_pred):.4f}")
    
    # Ensure model directory exists
    os.makedirs('model', exist_ok=True)
    model_path = os.path.join('model', 'rf_model.joblib')
    
    # Also save the feature columns so we know what order to pass them in during prediction
    features_path = os.path.join('model', 'model_features.joblib')
    
    print(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    joblib.dump(list(X.columns), features_path)
    print("Training complete.")

if __name__ == "__main__":
    train_model()
