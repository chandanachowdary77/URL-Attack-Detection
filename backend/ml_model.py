import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import os

MODEL_PATH = "url_model.pkl"


def train_model(csv_path):
    df = pd.read_csv(csv_path, on_bad_lines="skip")

    X = df["url"]
    y = df["attack_type"]

    model = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5))),
        ("clf", LogisticRegression(max_iter=1000))
    ])

    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)
    print("✅ Model trained and saved.")


def load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)


# ✅ Load once
model = load_model()


def predict_url(url):
    if not model:
        return "safe", 0.0

    prediction = model.predict([url])[0]
    confidence = max(model.predict_proba([url])[0])

    return prediction, float(confidence)
if __name__ == "__main__":
    train_model("dataset.csv")