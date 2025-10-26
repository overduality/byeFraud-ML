import joblib
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from scipy.stats import entropy
from scipy.sparse import hstack
import tldextract

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Set

app = FastAPI(
    title="Phishing Detection API",
    description="An API to predict whether a URL is phishing or legitimate.",
    version="2.0.0"
)

class URLRequest(BaseModel):
    urls: List[str]

class Prediction(BaseModel):
    URL: str
    Prediction: str
    Probability: float
    Confidence: float

class PredictionResponse(BaseModel):
    predictions: List[Prediction]

try:
    artifacts = joblib.load('lightgbm_advanced_model.pkl')
    model = artifacts['model']
    tfidf_char = artifacts['tfidf_char']
    tfidf_word = artifacts['tfidf_word']
    scaler = artifacts['scaler']
    features = artifacts['features']
    threshold = artifacts['threshold']
    print("Model artifacts loaded successfully.")
except FileNotFoundError:
    print("Error: File not found.")
    model = None

try:
    df_whitelist = pd.read_csv('WhiteList.csv')
    trusted_domains = {url.lower().strip().replace('www.', '') for url in df_whitelist['url']}
    print(f"Whitelist loaded with {len(trusted_domains)} trusted domains.")
except FileNotFoundError:
    print("⚠️ Warning: 'WhiteList.csv' not found. Running without a whitelist.")
    trusted_domains = set()

shared_platforms = {
    'github.io', 'pages.dev', 'r2.dev', 'canva.site', 'teachable.com',
    'blogspot.com', 'weebly.com', 'wix.com', 'carrd.co', 'car.blog'
}

sensitive_keywords = {
    'login', 'secure', 'account', 'verify', 'support', 'confirm', 'update',
    'password', 'billing', 'service', 'recover', 'signin', 'banking', 
    'payment', 'paypal', 'amazon', 'google', 'microsoft', 'apple', 
    'customer', 'alert', 'suspended', 'locked', 'expired', 'refund', 
    'invoice'
}

# --- Feature Extraction Functions ---
def extract_features(df):
    df = df.copy()
    
    df['url'] = df['url'].str.replace(r'\.', '.', regex=True)
    df['full_url_for_parsing'] = df['url'].apply(
        lambda x: 'http://' + x if isinstance(x, str) and not x.startswith(('http://', 'https://')) else x
    )

    def safe_parse_hostname(url):
        try:
            return urlparse(url).netloc
        except:
            if isinstance(url, str):
                url_clean = re.sub(r'^https?://', '', url)
                return url_clean.split('/')[0]
            return ''

    df['hostname'] = df['full_url_for_parsing'].apply(safe_parse_hostname)
    if 'domain' not in df.columns:
        df['domain'] = df['hostname']
    df['url_length'] = df['url'].apply(len)
    df['hostname_length'] = df['hostname'].apply(len)
    df['dot_count'] = df['url'].str.count(r'\.')
    df['hyphen_count'] = df['url'].str.count('-')
    df['at_symbol_count'] = df['url'].str.count('@')
    df['path_depth'] = df['url'].str.count('/')
    df['digit_count'] = df['url'].str.count(r'[0-9]')
    df['digit_ratio'] = df['digit_count'] / df['url_length'].replace(0, 1)
    df['has_ip_address'] = df['hostname'].str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').astype(int)
    df['subdomain_count'] = df['hostname'].apply(lambda x: len(x.split('.')) - 2 if x else 0).clip(lower=0)
    df['has_port'] = df['hostname'].str.contains(r':\d+', regex=True, na=False).astype(int)
    df['special_char_count'] = df['url'].apply(
        lambda x: sum(not c.isalnum() for c in x) if isinstance(x, str) else 0
    )
    df['special_char_ratio'] = df['special_char_count'] / df['url_length'].replace(0, 1)
    df['uppercase_ratio'] = df['url'].apply(
        lambda x: sum(1 for c in x if c.isupper()) / len(x) if len(x) > 0 else 0
    )
    df['hostname_entropy'] = df['hostname'].apply(
        lambda x: entropy(np.unique(list(x), return_counts=True)[1]) if x else 0
    )
    df['path_entropy'] = df['url'].apply(
        lambda x: entropy(np.unique(list(x.split('/')[-1]), return_counts=True)[1]) 
        if '/' in x and x.split('/')[-1] else 0
    )
    df['has_shortener'] = df['hostname'].str.contains(
        r'(bit\.ly|tinyurl|t\.co|goo\.gl)', regex=True, na=False
    ).astype(int)
    df['consecutive_dots'] = df['url'].str.count(r'\.{2,}')

    return df

def extract_advanced_phishing_features(df):
    df = df.copy()
    def detect_impersonation_domain(url):
        try:
            ext = tldextract.extract(url)
            main_domain = f"{ext.domain}.{ext.suffix}"
            subdomain = ext.subdomain
            
            if not subdomain:
                return 0
            
            subdomain_ext = tldextract.extract(subdomain)
            if subdomain_ext.domain and subdomain_ext.suffix:
                grandparent_domain = f"{subdomain_ext.domain}.{subdomain_ext.suffix}"
                if grandparent_domain != main_domain and grandparent_domain != subdomain:
                    return 1
            
            common_tlds = ['com', 'net', 'org', 'de', 'co.uk', 'fr', 'it', 'es', 'jp', 'cn', 'in', 'br', 'ru']
            for tld in common_tlds:
                pattern = r'([a-zA-Z0-9-]+)\.' + tld.replace('.', r'\.')
                matches = re.findall(pattern, subdomain)
                for match in matches:
                    potential_domain = f"{match}.{tld}"
                    if potential_domain != main_domain:
                        return 1
            return 0
        except:
            return 0
    
    # 2. SUBDOMAIN ANOMALY SCORE
    def calculate_subdomain_suspicion_score(url):
        try:
            ext = tldextract.extract(url)
            subdomain = ext.subdomain.lower()
            
            if not subdomain:
                return 0
            
            score = 0
            
            for keyword in sensitive_keywords:
                if keyword in subdomain:
                    score += 1
            
            if subdomain.count('-') > 1:
                score += 1
            
            if len(subdomain) > 20:
                score += 1
            
            if re.search(r'\d{3,}', subdomain):
                score += 1
            
            if '.' in subdomain:
                score += 1
                
            return score
        except:
            return 0
    
    def domain_contains_hyphen(url):
        try:
            ext = tldextract.extract(url)
            domain = ext.domain
            return 1 if '-' in domain else 0
        except:
            return 0
    
    def get_subdomain_depth(url):
        try:
            ext = tldextract.extract(url)
            return len(ext.subdomain.split('.')) if ext.subdomain else 0
        except:
            return 0
    
    df['has_impersonation_domain'] = df['url'].apply(detect_impersonation_domain)
    df['subdomain_suspicion_score'] = df['url'].apply(calculate_subdomain_suspicion_score)
    df['domain_contains_hyphen'] = df['url'].apply(domain_contains_hyphen)
    df['subdomain_depth'] = df['url'].apply(get_subdomain_depth)
    
    return df

def check_whitelist(url: str) -> tuple[bool, str]:
    try:
        extracted = tldextract.extract(url)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        
        if registered_domain not in trusted_domains:
            return False, "Domain not in whitelist"

        if registered_domain in shared_platforms and subdomain:
            return False, f"Suspicious subdomain on shared platform: {registered_domain}"
        
        if not subdomain:
            return True, f"Trusted root domain: {registered_domain}"

        subdomain_extract = tldextract.extract(subdomain)
        subdomain_registered_domain = f"{subdomain_extract.domain}.{subdomain_extract.suffix}"
        if subdomain_extract.domain and subdomain_registered_domain != registered_domain:
             return False, f"Brand impersonation detected: '{subdomain_registered_domain}' found in subdomain of '{registered_domain}'"

        subdomain_parts = set(re.split(r'[\.\-]', subdomain))
        if any(keyword in subdomain_parts for keyword in sensitive_keywords):
            return False, f"Sensitive keyword found in subdomain of '{registered_domain}'"
        
        if len(subdomain) > 25 or subdomain.count('-') > 2:
            return False, f"Anomalous subdomain structure on '{registered_domain}'"

        return True, f"Trusted domain with vetted subdomain: {registered_domain}"
        
    except Exception as e:
        return False, f"Error during whitelist check: {str(e)}"

@app.post("/predict", response_model=PredictionResponse)
async def predict_urls(request: URLRequest):
    if model is None:
        return {"error": "Model not loaded. Cannot make predictions."}

    predictions = []
    
    for url in request.urls:
        is_safe_by_whitelist, reason = check_whitelist(url)
        
        if is_safe_by_whitelist:
            predictions.append(
                Prediction(
                    URL=url,
                    Prediction='LEGITIMATE',
                    Probability=0.0,
                    Confidence=1.0
                )
            )
            continue
        
        new_df = pd.DataFrame({'url': [url]})
        new_df = extract_features(new_df)
        new_df = extract_advanced_phishing_features(new_df)
        new_df[features] = new_df[features].fillna(0)
        
        new_tfidf_char = tfidf_char.transform(new_df['url'])
        new_tfidf_word = tfidf_word.transform(new_df['url'])
        new_lexical = scaler.transform(new_df[features])
        
        new_combined = hstack([new_lexical, new_tfidf_char, new_tfidf_word]).tocsr()
        probability = model.predict_proba(new_combined)[0, 1]
        
        prediction = 'PHISHING' if probability >= threshold else 'LEGITIMATE'
        confidence = np.abs(probability - 0.5) * 2
        
        predictions.append(
            Prediction(
                URL=url,
                Prediction=prediction,
                Probability=float(probability),
                Confidence=float(confidence)
            )
        )
    
    return PredictionResponse(predictions=predictions)

@app.get("/", include_in_schema=False)
async def root():
    return {"message": "Phishing Detection API is running. Go to /docs for the API documentation."}