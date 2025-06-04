import streamlit as st
import joblib

# Load model
model = joblib.load('model_rf.joblib')
vectorizer = joblib.load('vectorizer.joblib')

st.title("Phishing URL Detection")

url_input = st.text_input("Enter a URL to check:")

if st.button("Check URL"):
    vect_url = vectorizer.transform([url_input])
    prediction = model.predict(vect_url)[0]
    if prediction == 1:
        st.error("⚠️ This URL is likely **Phishing**.")
    else:
        st.success("✅ This URL appears to be **Legitimate**.")
