import re

import numpy as np

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "limited time", "expires",
    "suspended", "verify", "confirm", "click here", "update now",
    "account locked", "unusual activity",
]


def clean_text(text: str) -> str:
    """Lowercase, strip HTML tags, strip special characters, collapse whitespace."""
    text = str(text or "")
    text = text.lower()
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def extract_features(text: str) -> np.ndarray:
    """Hand-crafted feature vector for a raw (uncleaned) email text.

    Must produce the exact same features at training time and prediction
    time, so this is the single source of truth imported by both
    train_model.py and api/index.py.
    """
    raw = str(text or "")
    lower = raw.lower()

    urgency_word_count = sum(lower.count(word) for word in URGENCY_WORDS)
    exclamation_count = raw.count('!')
    all_caps_word_count = sum(1 for w in re.findall(r'\b[A-Za-z]+\b', raw) if w.isupper() and len(w) > 1)
    url_count = lower.count('http')
    dollar_sign_count = raw.count('$')
    email_length = len(raw)
    has_attachment_mention = 1 if re.search(r'attach(ed|ment)', lower) else 0

    return np.array([
        urgency_word_count,
        exclamation_count,
        all_caps_word_count,
        url_count,
        dollar_sign_count,
        email_length,
        has_attachment_mention,
    ], dtype=np.float64)


FEATURE_NAMES = [
    "urgency_word_count",
    "exclamation_count",
    "all_caps_word_count",
    "url_count",
    "dollar_sign_count",
    "email_length",
    "has_attachment_mention",
]
