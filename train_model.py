import json
import gzip
import pickle

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from feature_extractor import clean_text, extract_features

MODEL_PATH = "model.pkl.gz"
VECTORIZER_PATH = "vectorizer.pkl"
EVALUATION_REPORT_PATH = "evaluation_report.json"

DATASETS = [
    {"path": "phishing_email.csv", "text_cols": ["text_combined"], "label_col": "label"},
    {"path": "CEAS_08.csv", "text_cols": ["subject", "body"], "label_col": "label"},
    {"path": "Enron.csv", "text_cols": ["subject", "body"], "label_col": "label"},
    {"path": "Ling.csv", "text_cols": ["subject", "body"], "label_col": "label"},
    {"path": "Nazario.csv", "text_cols": ["subject", "body"], "label_col": "label"},
    {"path": "Nigerian_Fraud.csv", "text_cols": ["subject", "body"], "label_col": "label"},
    {"path": "SpamAssasin.csv", "text_cols": ["subject", "body"], "label_col": "label"},
]


def load_and_normalize(path: str, text_cols: list[str], label_col: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [column for column in text_cols + [label_col] if column not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing expected columns {missing}; found {list(df.columns)}")

    text = df[text_cols[0]].fillna("").astype(str)
    for column in text_cols[1:]:
        text = text + " " + df[column].fillna("").astype(str)

    normalized = pd.DataFrame({"text": text, "label": df[label_col]})
    print(f"  loaded {len(normalized)} rows from {path}")
    return normalized


def load_dataset() -> pd.DataFrame:
    frames = [load_and_normalize(spec["path"], spec["text_cols"], spec["label_col"]) for spec in DATASETS]
    combined = pd.concat(frames, ignore_index=True)
    print(f"Total rows loaded from all {len(DATASETS)} datasets combined: {len(combined)}")

    combined = combined.dropna(subset=["text", "label"])
    combined["label"] = combined["label"].astype(int)
    combined = combined.drop_duplicates(subset=["text"])
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Rows remaining after dropping duplicates: {len(combined)}")
    return combined


def build_feature_matrix(raw_texts, vectorizer: TfidfVectorizer, fit: bool):
    cleaned = [clean_text(text) for text in raw_texts]
    tfidf_matrix = vectorizer.fit_transform(cleaned) if fit else vectorizer.transform(cleaned)
    handcrafted = np.vstack([extract_features(text) for text in raw_texts])
    return hstack([tfidf_matrix, csr_matrix(handcrafted)]).tocsr()


def evaluate_model(name: str, model, x_test, y_test) -> tuple[float, dict]:
    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)
    matrix = confusion_matrix(y_test, predictions).tolist()
    report = classification_report(y_test, predictions, target_names=["legitimate", "phishing"])
    report_dict = classification_report(y_test, predictions, target_names=["legitimate", "phishing"], output_dict=True)

    print(f"\n=== {name} ===")
    print(report)
    print(
        f"Accuracy: {accuracy:.4f}  |  Precision: {precision:.4f}  |  "
        f"Recall: {recall:.4f}  |  F1-score: {f1:.4f}"
    )
    print(f"Confusion matrix: {matrix}")

    return f1, {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": matrix,
        "classification_report": report_dict,
    }


def main():
    print("Loading and combining all 7 datasets ...")
    df = load_dataset()
    print(f"Final dataset: {len(df)} rows ({df['label'].sum()} phishing / {(df['label'] == 0).sum()} legitimate)")

    x_train_raw, x_test_raw, y_train, y_test = train_test_split(
        df["text"].tolist(),
        df["label"].tolist(),
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    x_train = build_feature_matrix(x_train_raw, vectorizer, fit=True)
    x_test = build_feature_matrix(x_test_raw, vectorizer, fit=False)

    candidates = {
        "Logistic Regression": LogisticRegression(class_weight="balanced", max_iter=3000),
        "Random Forest": RandomForestClassifier(class_weight="balanced", n_estimators=200, random_state=42),
    }

    evaluation_report = {"models": {}}
    best_name = None
    best_model = None
    best_f1 = -1.0

    for name, model in candidates.items():
        model.fit(x_train, y_train)
        f1, metrics = evaluate_model(name, model, x_test, y_test)
        evaluation_report["models"][name] = metrics
        if f1 > best_f1:
            best_name = name
            best_model = model
            best_f1 = f1

    evaluation_report["best_model"] = best_name
    print(f"\nBest model: {best_name} (F1={best_f1:.4f}) - saving as {MODEL_PATH}")

    with gzip.open(MODEL_PATH, "wb", compresslevel=9) as model_file:
        pickle.dump(best_model, model_file, protocol=pickle.HIGHEST_PROTOCOL)
    with open(VECTORIZER_PATH, "wb") as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)
    with open(EVALUATION_REPORT_PATH, "w", encoding="utf-8") as report_file:
        json.dump(evaluation_report, report_file, indent=2)

    print(f"Saved {MODEL_PATH}, {VECTORIZER_PATH}, and {EVALUATION_REPORT_PATH}")


if __name__ == "__main__":
    main()
