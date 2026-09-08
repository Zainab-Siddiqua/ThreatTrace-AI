import joblib
import re
from pathlib import Path

# Resolve directory path relative to this script file
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

# Load serialized model artifacts on module import
vectorizer = joblib.load(MODEL_DIR / "vectorizer.pkl")
classifier = joblib.load(MODEL_DIR / "classifier.pkl")

def _clean_text(text: str) -> str:
    """Preprocesses input text identically to the training pipeline."""
    text = str(text).lower()
    text = re.sub(r'http\S+|www\S+|\S+\@\S+', ' ', text)
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def analyze_content(subject: str, body: str) -> int:
    """
    Predicts threat likelihood from email text.
    Returns: Integer threat percentage from 0 to 100.
    """
    full_text = f"{subject} {body}"
    cleaned_text = _clean_text(full_text)
    
    if not cleaned_text:
        return 0

    # 1. Transform text to TF-IDF numerical vector
    vec = vectorizer.transform([cleaned_text])
    
    # 2. Get probability of phishing (class 1)
    phishing_prob = classifier.predict_proba(vec)[0][1]
    
    # 3. Return rounded score out of 100
    return int(round(phishing_prob * 100))