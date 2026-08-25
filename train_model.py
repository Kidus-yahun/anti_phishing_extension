import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Synthetic training dataset representing realistic phishing vs legitimate communications
TRAINING_DATA = [
    # --- PHISHING SAMPLES (Label 1) ---
    ("URGENT: Your PayPal account has been suspended due to unauthorized login attempt. Click here to verify credentials immediately.", 1),
    ("Security Alert: We detected unusual sign-in activity on your Netflix account. Update billing details within 24 hours to prevent cancellation.", 1),
    ("Action Required: Your Bank of America online banking session was locked. Re-enter your password and SSN to unlock.", 1),
    ("Final Notice: Your tax refund of $1,450 is ready. Click the link to claim your reward via gift card or direct deposit.", 1),
    ("Google Security: Someone knows your password. Update your password now at http://g00gle-security-update.xyz/login.", 1),
    ("IT Helpdesk Alert: Mandatory email system migration required. Verify your corporate credentials or your inbox will be terminated.", 1),
    ("Urgent Wire Transfer Request: I am in a meeting, please initiate a transfer of $5,000 to vendor immediately.", 1),
    ("Your Apple ID has been locked for security reasons. Click here to confirm identity and unlock.", 1),
    ("Amazon Order Confirmation: You purchased iPhone 15 Pro for $1,299. If you did not place this order, click here to cancel.", 1),
    ("Unusual sign in from Russia detected on your Microsoft account. Verify account credentials now.", 1),
    ("Your package delivery failed. Pay $2.99 redelivery fee now at http://192.168.1.50/post-tracking.", 1),
    ("Suspicious activity detected on Chase account. Click http://chase-update-security.top to restore access.", 1),

    # --- LEGITIMATE / HAM SAMPLES (Label 0) ---
    ("Hi John, here is the weekly project status report attached for your review. Let me know if you have questions.", 0),
    ("Your monthly electricity statement is now available. Log in to your utility portal to view the details.", 0),
    ("Hey, are we still meeting for lunch today at 12:30 PM?", 0),
    ("Thank you for your recent purchase at Target. Your receipt is attached below.", 0),
    ("Reminder: Team sync call scheduled tomorrow at 10:00 AM via Microsoft Teams.", 0),
    ("Here is the updated documentation for the API endpoints we discussed yesterday.", 0),
    ("Your flight reservation with Delta Airlines is confirmed. Confirmation code: XYZ123.", 0),
    ("Happy birthday! Wishing you a wonderful day filled with joy and celebration.", 0),
    ("The code pull request #42 has been merged into the main branch successfully.", 0),
    ("Please find attached the invoice for consulting services rendered in July.", 0)
]

def train_and_save_model():
    print("[Training Engine] Preparing datasets...")
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    print("[Training Engine] Extracting TF-IDF features and training Logistic Regression model...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english', min_df=1)
    features = vectorizer.fit_transform(texts)

    classifier = LogisticRegression(C=1.0)
    classifier.fit(features, labels)

    os.makedirs("app/models", exist_ok=True)
    model_path = "app/models/phishing_model.pkl"

    with open(model_path, "wb") as f:
        pickle.dump({
            "vectorizer": vectorizer,
            "classifier": classifier
        }, f)

    print(f"[Training Engine] Model successfully trained and saved to '{model_path}'!")

if __name__ == "__main__":
    train_and_save_model()
