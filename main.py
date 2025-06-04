import streamlit as st
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re

# Load the trained model and vectorizer
@st.cache_resource
def load_model():
    model = joblib.load('random_forest_model.joblib')
    vectorizer = joblib.load('count_vectorizer.joblib')
    return model, vectorizer

def extract_features(url):
    """Extract features from URL for phishing detection"""
    features = {}
    
    # Parse URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # Length features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    
    # Character count features (reduced to match model)
    features['dot_count'] = url.count('.')
    features['dash_count'] = url.count('-')
    features['underscore_count'] = url.count('_')
    features['slash_count'] = url.count('/')
    features['question_count'] = url.count('?')
    features['equal_count'] = url.count('=')
    features['at_count'] = url.count('@')
    features['and_count'] = url.count('&')
    features['exclamation_count'] = url.count('!')
    features['space_count'] = url.count(' ')
    features['tilde_count'] = url.count('~')
    features['comma_count'] = url.count(',')
    features['plus_count'] = url.count('+')
    features['asterisk_count'] = url.count('*')
    features['hash_count'] = url.count('#')
    features['dollar_count'] = url.count('$')
    features['percent_count'] = url.count('%')
    
    # Suspicious patterns
    features['has_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0
    
    return features

def predict_phishing(url, model, vectorizer):
    """Predict if URL is phishing"""
    # Extract features
    features = extract_features(url)
    
    # Create feature vector (21 features to match trained model)
    feature_names = [
        'url_length', 'domain_length', 'path_length', 'dot_count', 'dash_count',
        'underscore_count', 'slash_count', 'question_count', 'equal_count',
        'at_count', 'and_count', 'exclamation_count', 'space_count', 'tilde_count',
        'comma_count', 'plus_count', 'asterisk_count', 'hash_count', 'dollar_count',
        'percent_count', 'has_ip'
    ]
    
    # Create feature array in the correct order
    feature_array = []
    for feature_name in feature_names:
        feature_array.append(features.get(feature_name, 0))
    
    # Convert to numpy array and reshape for single prediction
    feature_array = np.array(feature_array).reshape(1, -1)
    
    # Make prediction
    prediction = model.predict(feature_array)[0]
    probability = model.predict_proba(feature_array)[0]
    
    # Enhanced phishing detection with stronger heuristics
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    full_url = url.lower()
    
    suspicious_score = 0
    phishing_indicators = []
    
    # Check for IP addresses (major red flag)
    if features['has_ip']:
        suspicious_score += 0.6
        phishing_indicators.append("IP address detected")
    
    # Check for suspicious domain patterns (brand impersonation)
    legitimate_domains = ['paypal.com', 'amazon.com', 'microsoft.com', 'chase.com', 'apple.com', 'google.com']
    suspicious_brand_words = ['paypal', 'amazon', 'microsoft', 'chase', 'apple', 'google', 'bank', 'secure']
    
    # If domain contains brand name but isn't the legitimate domain
    for brand in suspicious_brand_words:
        if brand in domain and not any(legit in domain for legit in legitimate_domains):
            suspicious_score += 0.5
            phishing_indicators.append(f"Suspicious domain containing '{brand}'")
            break
    
    # Check for common phishing keywords
    phishing_keywords = ['verify', 'update', 'confirm', 'signin', 'login', 'security', 'alert', 'suspended', 'locked']
    keyword_count = sum(1 for keyword in phishing_keywords if keyword in full_url)
    if keyword_count >= 2:
        suspicious_score += 0.4
        phishing_indicators.append(f"Multiple phishing keywords ({keyword_count})")
    elif keyword_count == 1:
        suspicious_score += 0.2
        phishing_indicators.append("Phishing keywords detected")
    
    # Check for suspicious URL patterns
    if features['url_length'] > 150:
        suspicious_score += 0.3
        phishing_indicators.append("Extremely long URL")
    elif features['url_length'] > 80:
        suspicious_score += 0.1
        phishing_indicators.append("Long URL")
    
    # Check for excessive special characters (common in phishing)
    special_char_count = (features['dash_count'] + features['underscore_count'] + 
                         features['question_count'] + features['equal_count'] + 
                         features['and_count'] + features['at_count'])
    if special_char_count > 10:
        suspicious_score += 0.3
        phishing_indicators.append("Excessive special characters")
    
    # Check for suspicious TLDs or subdomains
    suspicious_patterns = ['-', '.tk', '.ml', '.ga', '.cf', 'bit.ly', 'tinyurl']
    for pattern in suspicious_patterns:
        if pattern in domain and pattern != domain:
            suspicious_score += 0.2
            phishing_indicators.append(f"Suspicious pattern: {pattern}")
            break
    
    # Final decision logic - if suspicious score is high, override model
    if suspicious_score >= 0.4:
        # Force phishing classification
        prediction = 1
        confidence = min(0.95, 0.5 + suspicious_score)
        probability = np.array([1 - confidence, confidence])
        phishing_indicators.append(f"Manual override (score: {suspicious_score:.2f})")
    else:
        # Use original model prediction but adjust if slightly suspicious
        if suspicious_score > 0.1 and prediction == 0:
            # Reduce confidence in legitimate classification
            probability[0] = max(0.5, probability[0] - suspicious_score)
            probability[1] = 1 - probability[0]
    
    return prediction, probability

def main():
    st.set_page_config(
        page_title="Phishing Website Detector",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Phishing Website Detector")
    st.markdown("**Detect potentially malicious URLs using Machine Learning**")
    
    # Load model
    try:
        model, vectorizer = load_model()
        st.success("✅ Model loaded successfully!")
    except Exception as e:
        st.error(f"❌ Error loading model: {str(e)}")
        st.stop()
    
    # Create two columns
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Enter URL to Check")
        url_input = st.text_input(
            "URL:",
            placeholder="https://example.com",
            help="Enter the complete URL you want to check"
        )
        
        check_button = st.button("🔍 Check URL", type="primary")
        
        if check_button and url_input:
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner("Analyzing URL..."):
                try:
                    prediction, probability = predict_phishing(url_input, model, vectorizer)
                    
                    # Display results
                    st.subheader("Analysis Results")
                    
                    if prediction == 1:  # Phishing
                        st.error("🚨 **PHISHING DETECTED**")
                        st.error(f"This URL appears to be malicious with {probability[1]:.2%} confidence")
                    else:  # Legitimate
                        st.success("✅ **LEGITIMATE URL**")
                        st.success(f"This URL appears to be safe with {probability[0]:.2%} confidence")
                    
                    # Show probability breakdown
                    st.subheader("Confidence Scores")
                    col_leg, col_phi = st.columns(2)
                    
                    with col_leg:
                        st.metric("Legitimate", f"{probability[0]:.2%}")
                    with col_phi:
                        st.metric("Phishing", f"{probability[1]:.2%}")
                    
                    # Progress bars
                    st.progress(probability[0], text=f"Legitimate: {probability[0]:.2%}")
                    st.progress(probability[1], text=f"Phishing: {probability[1]:.2%}")
                    
                    # URL features
                    with st.expander("📊 URL Analysis Details"):
                        features = extract_features(url_input)
                        
                        feature_col1, feature_col2 = st.columns(2)
                        
                        with feature_col1:
                            st.write("**Length Features:**")
                            st.write(f"- URL Length: {features['url_length']}")
                            st.write(f"- Domain Length: {features['domain_length']}")
                            st.write(f"- Path Length: {features['path_length']}")
                            
                            st.write("**Security Features:**")
                            st.write(f"- Has IP Address: {'Yes' if features['has_ip'] else 'No'}")
                            st.write(f"- Special Characters: {features['at_count'] + features['and_count']}")
                            st.write(f"- Symbols: {features['exclamation_count'] + features['hash_count']}")
                        
                        with feature_col2:
                            st.write("**Character Count:**")
                            st.write(f"- Dots: {features['dot_count']}")
                            st.write(f"- Dashes: {features['dash_count']}")
                            st.write(f"- Slashes: {features['slash_count']}")
                            st.write(f"- Question marks: {features['question_count']}")
                
                except Exception as e:
                    st.error(f"❌ Error analyzing URL: {str(e)}")
        
        elif check_button and not url_input:
            st.warning("⚠️ Please enter a URL to check")
    
    with col2:
        st.subheader("ℹ️ About")
        st.info("""
        This tool uses a Random Forest machine learning model to detect potentially malicious URLs.
        
        **Features analyzed:**
        - URL structure and length
        - Character patterns
        - Domain characteristics
        - Security indicators
        - Suspicious keywords
        """)
        
        st.subheader("🔍 How it works")
        st.write("""
        1. Enter a URL in the input field
        2. Click 'Check URL' to analyze
        3. View the prediction and confidence scores
        4. Check detailed analysis in the expandable section
        """)
        
        st.subheader("⚠️ Disclaimer")
        st.warning("""
        This tool is for educational purposes. 
        Always exercise caution when visiting unknown websites.
        """)

if __name__ == "__main__":
    main()
