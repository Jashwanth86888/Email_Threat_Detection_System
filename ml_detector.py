"""
ml_detector.py - Machine Learning Email Threat Detection Module
==============================================================
Demonstrates AI / ML concepts for Computer Networks & Cybersecurity:
1. Feature Extraction:
   - Text NLP Features via TF-IDF (Term Frequency - Inverse Document Frequency)
   - Structural Network Features (URL counts, IP in URL, HTTP vs HTTPS, Sender alignment)
2. Classification Model:
   - Logistic Regression with calibrated probability scoring: P(Phishing) in [0, 1]
   - Scaled to 0-100 points: ML_Score = round(P(Phishing) * 100)
3. Explainable AI (XAI):
   - Extracts top contributing predictive features (words and structural indicators)
4. Hybrid Ensemble:
   - Final_Score = round((Rule_Based_Score + ML_Score) / 2)

Author: Team 21 (Vasavi College of Engineering, CN 5th Sem)
"""

import os
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
import joblib

MODEL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "email_threat_ml_model.joblib")


# -------------------------------------------------------------
# 1. TRAINING DATASET (Legitimate vs Phishing/Fraud Emails)
# -------------------------------------------------------------
TRAINING_SAMPLES = [
    # --- LEGITIMATE SAMPLES (Label: 0) ---
    {
        "text": "Your GitHub security advisory alert closed. The automated security scan on your repository has completed successfully. All dependencies are verified.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.05,
        "label": 0
    },
    {
        "text": "HackerRank Coding Test Invitation. Please verify your email address to start coding. Review coding questions and schedule.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.06,
        "label": 0
    },
    {
        "text": "Vasavi College of Engineering Computer Networks 5th semester class timetable and lab schedule update. Please find syllabus attached.",
        "url_count": 0, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.08,
        "label": 0
    },
    {
        "text": "Google Calendar invitation: Project review meeting tomorrow at 10 AM. Location: Conference Room B and Google Meet link.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.07,
        "label": 0
    },
    {
        "text": "Your monthly electricity bill receipt from TSSPDEL. Payment of 1450 rupees received successfully through UPI. Transaction ID confirmed.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.05,
        "label": 0
    },
    {
        "text": "Amazon order delivered: Your package containing book has been handed to resident. Thank you for shopping with Amazon.",
        "url_count": 2, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.04,
        "label": 0
    },
    {
        "text": "LinkedIn notification: 3 connections viewed your profile this week. Connect with fellow software engineers and alumni.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.06,
        "label": 0
    },
    {
        "text": "Coursera weekly progress report: You completed Module 3 of Computer Networks and TCP/IP protocol suite. Keep learning.",
        "url_count": 1, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.05,
        "label": 0
    },
    {
        "text": "OpenAI ChatGPT Plus subscription receipt and monthly tax invoice. Manage your account settings and billing preferences.",
        "url_count": 2, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.07,
        "label": 0
    },
    {
        "text": "Internal IT department maintenance: Campus WiFi router firmware update scheduled on Sunday midnight. No downtime expected.",
        "url_count": 0, "has_ip_url": 0, "has_http": 0, "domain_mismatch": 0, "auth_fail": 0, "caps_ratio": 0.09,
        "label": 0
    },

    # --- PHISHING / FRAUD SAMPLES (Label: 1) ---
    {
        "text": "URGENT: Your SBI bank account suspended immediately due to unauthorized login attempt. Click here within 24 hours to verify debit card and OTP.",
        "url_count": 1, "has_ip_url": 1, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.35,
        "label": 1
    },
    {
        "text": "PayPal Security Alert: Unusual activity detected and password expired. Immediate action required. Confirm your identity or account restricted.",
        "url_count": 2, "has_ip_url": 0, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.22,
        "label": 1
    },
    {
        "text": "HDFC Bank customer notice: Your netbanking will be blocked today due to pending KYC update. Update PAN and Aadhaar immediately.",
        "url_count": 1, "has_ip_url": 1, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.28,
        "label": 1
    },
    {
        "text": "CONGRATULATIONS! You have won $1,500,000 in international lottery. Provide your bank account details and wire transfer fee immediately.",
        "url_count": 1, "has_ip_url": 1, "has_http": 1, "domain_mismatch": 1, "auth_fail": 0, "caps_ratio": 0.40,
        "label": 1
    },
    {
        "text": "Microsoft Office365 alert: Password expired today. You will lose access to mailbox in 2 hours unless you login here.",
        "url_count": 1, "has_ip_url": 0, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.18,
        "label": 1
    },
    {
        "text": "Income Tax refund notification: You have unclaimed tax refund of Rs 48,500. Click link to submit debit card CVV for instant credit.",
        "url_count": 1, "has_ip_url": 1, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.25,
        "label": 1
    },
    {
        "text": "Netflix billing declined: Your membership will be cancelled within 12 hours. Update credit card payment information now.",
        "url_count": 1, "has_ip_url": 0, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.20,
        "label": 1
    },
    {
        "text": "FedEx package delivery suspended: Undelivered parcel waiting at customs. Pay $2.99 clearance charge immediately or package destroyed.",
        "url_count": 1, "has_ip_url": 0, "has_http": 1, "domain_mismatch": 1, "auth_fail": 0, "caps_ratio": 0.22,
        "label": 1
    },
    {
        "text": "Crypto wallet MetaMask alert: Unauthorized withdrawal request of 2.5 ETH. Cancel transaction immediately by entering secret seed phrase.",
        "url_count": 1, "has_ip_url": 1, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.30,
        "label": 1
    },
    {
        "text": "URGENT Action Required: Threat of closure on your domain registration. Click here to verify ownership and avoid immediate suspension.",
        "url_count": 2, "has_ip_url": 0, "has_http": 1, "domain_mismatch": 1, "auth_fail": 1, "caps_ratio": 0.26,
        "label": 1
    }
]


# -------------------------------------------------------------
# 2. FEATURE EXTRACTION HELPERS
# -------------------------------------------------------------
class StructuralFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts numerical metadata and network indicators from email data.
    """
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for item in X:
            features.append([
                float(item.get("url_count", 0)),
                float(item.get("has_ip_url", 0)),
                float(item.get("has_http", 0)),
                float(item.get("domain_mismatch", 0)),
                float(item.get("auth_fail", 0)),
                float(item.get("caps_ratio", 0.0))
            ])
        return np.array(features)


def extract_features_from_parsed_data(parsed_data):
    """
    Transforms parsed email metadata into structured input for the ML model.
    """
    subject = parsed_data.get("subject", "")
    body_text = parsed_data.get("body_text", "")
    combined_text = f"{subject} {body_text}".strip()
    
    # Calculate uppercase ratio
    total_chars = len(combined_text)
    caps_count = sum(1 for c in combined_text if c.isupper())
    caps_ratio = (caps_count / total_chars) if total_chars > 0 else 0.0

    urls = parsed_data.get("urls", [])
    has_ip = 1 if any(u.get("is_ip_based") for u in urls) else 0
    has_http = 1 if any(u.get("is_http") and not u.get("is_schema") for u in urls) else 0

    sender_domain = parsed_data.get("sender_email", "").split("@")[-1].lower() if "@" in parsed_data.get("sender_email", "") else ""
    return_path = parsed_data.get("return_path", "").split("@")[-1].lower() if "@" in parsed_data.get("return_path", "") else ""
    
    domain_mismatch = 1 if (return_path and sender_domain and sender_domain not in return_path and return_path not in sender_domain) else 0
    
    auth_results = parsed_data.get("auth_results", "").lower()
    received_spf = parsed_data.get("received_spf", "").lower()
    auth_fail = 1 if ("spf=fail" in auth_results or "fail" in received_spf or "dmarc=fail" in auth_results) else 0

    return {
        "text": combined_text,
        "url_count": len(urls),
        "has_ip_url": has_ip,
        "has_http": has_http,
        "domain_mismatch": domain_mismatch,
        "auth_fail": auth_fail,
        "caps_ratio": round(caps_ratio, 3)
    }


# -------------------------------------------------------------
# 3. MODEL TRAINING & PERSISTENCE
# -------------------------------------------------------------
def train_and_save_model():
    """
    Trains a TF-IDF + Structural Logistic Regression classifier and saves it.
    """
    texts = [s["text"] for s in TRAINING_SAMPLES]
    y = np.array([s["label"] for s in TRAINING_SAMPLES])
    
    # TF-IDF Vectorizer for text patterns
    tfidf = TfidfVectorizer(ngram_range=(1, 2), max_features=120, stop_words='english')
    X_tfidf = tfidf.fit_transform(texts).toarray()
    
    # Structural features
    struct_extractor = StructuralFeatureExtractor()
    X_struct = struct_extractor.transform(TRAINING_SAMPLES)
    
    # Combined feature matrix
    X_combined = np.hstack([X_tfidf, X_struct])
    
    # Train Logistic Regression with L2 regularization
    clf = LogisticRegression(C=2.0, max_iter=200, random_state=42)
    clf.fit(X_combined, y)
    
    model_bundle = {
        "tfidf": tfidf,
        "struct_extractor": struct_extractor,
        "classifier": clf,
        "feature_names_tfidf": tfidf.get_feature_names_out(),
        "struct_feature_names": ["url_count", "has_ip_url", "has_http", "domain_mismatch", "auth_fail", "caps_ratio"]
    }
    
    joblib.dump(model_bundle, MODEL_FILE)
    return model_bundle


def get_model():
    """
    Loads model from disk or trains if not found.
    """
    if os.path.exists(MODEL_FILE):
        try:
            return joblib.load(MODEL_FILE)
        except Exception:
            return train_and_save_model()
    else:
        return train_and_save_model()


# -------------------------------------------------------------
# 4. PREDICTION & EXPLAINABILITY ENGINE
# -------------------------------------------------------------
def predict_ml_threat(parsed_data):
    """
    Evaluates an email using the trained AI/ML Model.
    
    Returns:
        dict:
            - ml_score: int (0 to 100)
            - phishing_probability: float (0.0 to 1.0)
            - confidence_level: str ("High", "Moderate", "Low")
            - top_features: list of dicts with detected indicators
            - model_name: str
    """
    model = get_model()
    feature_dict = extract_features_from_parsed_data(parsed_data)
    
    # Vectorize text
    tfidf_vec = model["tfidf"].transform([feature_dict["text"]]).toarray()
    
    # Extract structural features
    struct_vec = model["struct_extractor"].transform([feature_dict])
    
    # Combine
    X_test = np.hstack([tfidf_vec, struct_vec])
    
    # Predict probabilities: [P(Legitimate), P(Phishing)]
    proba = model["classifier"].predict_proba(X_test)[0]
    p_phishing = float(proba[1])
    
    # Scale to 0 - 100 integer points
    ml_score = int(round(p_phishing * 100))
    ml_score = min(100, max(0, ml_score))
    
    # Extract top contributing features (Explainable AI / XAI)
    coefs = model["classifier"].coef_[0]
    tfidf_names = model["feature_names_tfidf"]
    struct_names = model["struct_feature_names"]
    all_names = list(tfidf_names) + struct_names
    
    # Features present in this sample
    active_indices = np.where(X_test[0] > 0)[0]
    contributions = []
    for idx in active_indices:
        feat_name = all_names[idx]
        val = X_test[0][idx]
        weight = coefs[idx]
        # Impact = weight * value
        impact = weight * val
        contributions.append((feat_name, impact, weight))
        
    # Sort by positive impact (features pushing towards phishing)
    contributions.sort(key=lambda x: x[1], reverse=True)
    
    top_indicators = []
    for feat_name, impact, weight in contributions[:4]:
        if impact > 0.05:
            friendly_name = feat_name
            if feat_name == "has_ip_url":
                friendly_name = "Raw IP in URL"
            elif feat_name == "has_http":
                friendly_name = "Cleartext HTTP URL"
            elif feat_name == "domain_mismatch":
                friendly_name = "Sender & Return-Path Mismatch"
            elif feat_name == "auth_fail":
                friendly_name = "SPF/DKIM Authentication Failure"
            elif feat_name == "caps_ratio":
                friendly_name = "High Uppercase Urgency Ratio"
            else:
                friendly_name = f"Keyword pattern: '{feat_name}'"
                
            top_indicators.append({
                "feature": friendly_name,
                "importance": "High" if impact > 0.25 else "Moderate",
                "impact_type": "Increases Threat Score"
            })

    if p_phishing >= 0.70:
        confidence = "High Confidence (Phishing)"
    elif p_phishing <= 0.30:
        confidence = "High Confidence (Legitimate)"
    else:
        confidence = "Moderate / Borderline Confidence"

    return {
        "ml_score": ml_score,
        "phishing_probability": round(p_phishing, 3),
        "legit_probability": round(float(proba[0]), 3),
        "confidence_level": confidence,
        "top_features": top_indicators,
        "model_name": "TF-IDF N-Gram Vectorizer + Logistic Regression Classifier (L2 Regularized)",
        "feature_summary": {
            "url_count": feature_dict["url_count"],
            "has_ip_url": bool(feature_dict["has_ip_url"]),
            "has_http": bool(feature_dict["has_http"]),
            "auth_fail": bool(feature_dict["auth_fail"])
        }
    }


if __name__ == "__main__":
    print("Training / Testing AI-ML Email Threat Detector...")
    sample = {
        "subject": "URGENT: Verify your account immediately",
        "body_text": "Your account will be suspended within 24 hours. Click here: http://192.168.1.1/login",
        "urls": [{"is_ip_based": True, "is_http": True}],
        "sender_email": "support@bank-security.xyz",
        "return_path": "bounce@compromised.org",
        "auth_results": "spf=fail"
    }
    result = predict_ml_threat(sample)
    print("Predicted ML Score:", result["ml_score"])
    print("Phishing Probability:", result["phishing_probability"])
    print("Confidence:", result["confidence_level"])
    print("Top Features:", result["top_features"])
