# url_analyzer.py

import re
import os
import joblib
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
from math import log2


# define paths for loading the machine learning model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "xgb_url_classifier.joblib")

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.site', '.online', '.buzz', '.info', '.vip',
    '.loan', '.work', '.gq', '.ga', '.cf', '.tk', '.ml'
}

# calculate the entropy of a string, a measure of its randomness
def calculate_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    probabilities = [count / len(text) for count in counts.values()]

    return -sum(p * log2(p) for p in probabilities)

# extract a wide range of lexical and host-based features from a URL string to be used by the ML model
def extract_features_advanced(url):
    features = {}
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    path = parsed_url.path
    query = parsed_url.query

    # basic length features
    features['url_len'] = len(url)
    features['hostname_len'] = len(hostname)
    features['path_len'] = len(path)
    features['query_len'] = len(query)

    # count of special characters
    for char in ['-', '_', '/', '?', '=', '@', '%', '&', '.', '#']:
        features[f'count_{char}'] = url.count(char)

    # ratios and binary flags
    features['ratio_digits'] = sum(c.isdigit() for c in url) / len(url) if url else 0
    features['ratio_letters'] = sum(c.isalpha() for c in url) / len(url) if url else 0
    features['is_ip_address'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    features['has_http_in_path'] = 1 if 'http' in path.lower() or 'http' in query.lower() else 0
    
    # hostname-based features
    tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
    features['has_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
    features['subdomain_count'] = hostname.count('.')
    features['has_digit_in_hostname'] = 1 if any(c.isdigit() for c in hostname) else 0

    # path-based features
    path_tokens = [token for token in path.split('/') if token]
    features['path_token_count'] = len(path_tokens)
    if path_tokens:
        features['avg_path_token_len'] = sum(len(token) for token in path_tokens) / len(path_tokens)
        features['max_path_token_len'] = max(len(token) for token in path_tokens)
    else:
        features['avg_path_token_len'] = 0
        features['max_path_token_len'] = 0

    # entropy features
    features['url_entropy'] = calculate_entropy(url)
    features['hostname_entropy'] = calculate_entropy(hostname)
    features['path_entropy'] = calculate_entropy(path)
    
    return features

# class to analyze URLs using a pre-trained XGBoost model
class UrlAnalyzer:
    # load the pre-trained URL classifier model from a file
    def __init__(self):
        try:
            self.model = joblib.load(MODEL_PATH)
        except FileNotFoundError:
            print(f"[CRITICAL] URL analysis model not found at: {MODEL_PATH}")
            self.model = None

    # predict whether a URL is malicious using the loaded model
    def check_url(self, url: str):
        if not self.model:
            return {"error": "Model not loaded.", "is_malicious": False, "probability": 0.0}

        # extract features and format them into a dataframe for the model
        features = extract_features_advanced(url)
        X_new = pd.DataFrame([features])
        
        pred = self.model.predict(X_new)[0]
        proba = self.model.predict_proba(X_new)[0][1] # 악성일 확률
        
        return {
            "is_malicious": bool(pred),
            "probability": float(proba)
        }

