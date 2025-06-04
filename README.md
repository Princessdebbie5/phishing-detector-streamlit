# Phishing Detection System using Machine Learning

This project is a machine learning-based phishing website detection system, developed using the Random Forest algorithm. The model classifies URLs as either **legitimate** or **phishing** using features extracted from the URL text.

## 🔍 Dataset
- Dataset Source: [Kaggle - Phishing Website Detector](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector)
- Sample Size Used: 50,000 records
- Features: URL text, labeled as phishing or legitimate

## 🛠 Technologies Used
- Python
- Scikit-learn
- Pandas
- CountVectorizer and TF-IDF
- Random Forest Classifier
- Google Colab
- Streamlit (for UI demo)
- Joblib (for model serialization)

## 📊 Model Performance
- Accuracy with CountVectorizer: 85%
- Accuracy with TF-IDF: 84%
- Final model: Random Forest with CountVectorizer

## 🚀 How to Run
1. Load the saved model (`.joblib`) file
2. Use the `main.py` file to launch the Streamlit app
3. Predict whether a given URL is phishing or legitimate

## 👨‍💻 Author
- Obayendo Deborah

