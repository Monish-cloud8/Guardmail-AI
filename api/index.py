import os
import re
import sys
import json
import base64
import gzip
import pickle
import email.utils
from functools import wraps
from datetime import datetime, timezone
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import hstack, csr_matrix
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from feature_extractor import clean_text, extract_features, URGENCY_WORDS

load_dotenv()

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.getenv("SESSION_SECRET", "change_this_to_a_long_random_string")

CORS(app, supports_credentials=True)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:3000/auth/callback")

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

API_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(API_DIR, "model.pkl.gz")
LEGACY_MODEL_PATH = os.path.join(API_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(API_DIR, "vectorizer.pkl")
ROOT_MODEL_PATH = os.path.join(PROJECT_ROOT, "model.pkl.gz")
ROOT_LEGACY_MODEL_PATH = os.path.join(PROJECT_ROOT, "model.pkl")
ROOT_VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "vectorizer.pkl")
APP_STORAGE_PATH = os.path.abspath(
    os.getenv(
        "APP_STORAGE_PATH",
        os.path.join("/tmp", "app_storage.json") if os.getenv("VERCEL") else os.path.join(PROJECT_ROOT, "app_storage.json"),
    )
)
APP_STORAGE_CACHE = None

RISK_RULES = [
    {"label": "Scam Alert", "category": "SCAM_ALERT", "min_confidence": 0.95},
    {"label": "Suspicious", "category": "SPAM", "min_confidence": 0.85},
    {"label": "Review", "category": "HIGH_PRIORITY", "min_confidence": 0.70},
    {"label": "Safe", "category": "SAFE", "min_confidence": 0.0},
]

RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".html",
    ".zip", ".rar", ".7z", ".iso", ".docm", ".xlsm",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "rebrand.ly", "shorturl.at", "cutt.ly", "tiny.cc",
}

KNOWN_BRANDS = [
    "paypal.com", "google.com", "apple.com", "amazon.com", "microsoft.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "irs.gov",
    "netflix.com", "instagram.com", "facebook.com", "twitter.com",
    "linkedin.com", "dropbox.com",
]


def _load_pickle(path):
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None


ml_model = _load_pickle(MODEL_PATH)
if ml_model is None:
    ml_model = _load_pickle(LEGACY_MODEL_PATH)
if ml_model is None:
    ml_model = _load_pickle(ROOT_MODEL_PATH)
if ml_model is None:
    ml_model = _load_pickle(ROOT_LEGACY_MODEL_PATH)

ml_vectorizer = _load_pickle(VECTORIZER_PATH)
if ml_vectorizer is None:
    ml_vectorizer = _load_pickle(ROOT_VECTORIZER_PATH)
TFIDF_FEATURE_NAMES = ml_vectorizer.get_feature_names_out() if ml_vectorizer is not None else None


def _default_app_storage():
    return {"feedback": {}, "safe_senders": [], "blocked_senders": []}


def _load_app_storage():
    global APP_STORAGE_CACHE
    try:
        with open(APP_STORAGE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        if APP_STORAGE_CACHE is None:
            APP_STORAGE_CACHE = _default_app_storage()
        return APP_STORAGE_CACHE
    except Exception:
        if APP_STORAGE_CACHE is None:
            APP_STORAGE_CACHE = _default_app_storage()
        return APP_STORAGE_CACHE

    storage = _default_app_storage()
    storage["feedback"] = data.get("feedback", {}) if isinstance(data.get("feedback"), dict) else {}
    storage["safe_senders"] = sorted({str(v).strip().lower() for v in data.get("safe_senders", []) if str(v).strip()})
    storage["blocked_senders"] = sorted({str(v).strip().lower() for v in data.get("blocked_senders", []) if str(v).strip()})
    APP_STORAGE_CACHE = storage
    return storage


def _save_app_storage(storage: dict):
    global APP_STORAGE_CACHE
    APP_STORAGE_CACHE = storage
    try:
        storage_dir = os.path.dirname(APP_STORAGE_PATH)
        if storage_dir:
            os.makedirs(storage_dir, exist_ok=True)
        with open(APP_STORAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(storage, f, indent=2, ensure_ascii=False)
    except OSError:
        # Vercel functions expose a read-only filesystem outside /tmp.
        pass


def _clean_sender_email(value: str) -> str:
    return email.utils.parseaddr(value or "")[1].strip().lower()


def _domain_from_value(value: str) -> str:
    raw = _clean_sender_email(value)
    if "@" in raw:
        return raw.split("@", 1)[1]
    return ""


def _normalize_header_map(headers_list: list[dict]) -> dict:
    headers = {}
    for header in headers_list:
        name = header.get("name")
        value = header.get("value", "")
        if not name:
            continue
        if name in headers:
            headers[name] = f"{headers[name]}\n{value}"
        else:
            headers[name] = value
    return headers


def _looks_like_url(value: str) -> bool:
    return bool(re.search(r"https?://|www\.", value or "", flags=re.IGNORECASE))


def _extract_display_domain(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if _looks_like_url(text):
        try:
            parsed = urlparse(text if "://" in text else f"https://{text}")
        except ValueError:
            return ""
        return (parsed.hostname or "").lower()
    return ""


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            if char_a == char_b:
                current.append(prev[j - 1])
            else:
                current.append(1 + min(prev[j], current[-1], prev[j - 1]))
        prev = current
    return prev[-1]


def _domain_signals(domain: str) -> list[str]:
    normalized = (domain or "").strip().lower()
    if not normalized:
        return []

    signals = []
    if any(ord(char) > 0x024F for char in normalized) or "xn--" in normalized:
        signals.append("Possible spoofing")

    for brand in KNOWN_BRANDS:
        if normalized == brand:
            continue
        distance = _levenshtein(normalized, brand)
        if distance in (1, 2):
            signals.append("Sender mismatch")
            break
    return signals


def _brand_name_mismatch(sender_name: str, sender_domain: str) -> bool:
    normalized_name = (sender_name or "").lower()
    if not normalized_name or not sender_domain:
        return False

    for brand in KNOWN_BRANDS:
        brand_root = brand.split(".")[0]
        if brand_root in normalized_name and sender_domain != brand:
            return True
    return False


def _build_oauth_flow():
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [GOOGLE_REDIRECT_URI],
        }
    }
    return Flow.from_client_config(client_config, scopes=GMAIL_SCOPES, redirect_uri=GOOGLE_REDIRECT_URI)


def _credentials_to_session(creds: Credentials):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }


def _set_active_account(email: str, raw_creds: dict):
    accounts = session.get("accounts", {})
    accounts[email] = raw_creds
    session["accounts"] = accounts
    session["active_account_email"] = email
    session["credentials"] = raw_creds
    session["user_email"] = email


def _session_has_account() -> bool:
    return bool(session.get("active_account_email") and session.get("accounts", {}).get(session.get("active_account_email"))) or bool(session.get("credentials"))


def _credentials_from_session(active_email: str | None = None):
    accounts = session.get("accounts", {})
    selected_email = active_email or session.get("active_account_email")
    raw = accounts.get(selected_email) if selected_email else None
    if raw is None:
        raw = session.get("credentials")
    if not raw:
        return None

    expiry = datetime.fromisoformat(raw["expiry"]) if raw.get("expiry") else None
    creds = Credentials(
        token=raw["token"],
        refresh_token=raw.get("refresh_token"),
        token_uri=raw["token_uri"],
        client_id=raw["client_id"],
        client_secret=raw["client_secret"],
        scopes=raw["scopes"],
        expiry=expiry,
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleAuthRequest())
        refreshed_raw = _credentials_to_session(creds)
        if selected_email:
            _set_active_account(selected_email, refreshed_raw)
        else:
            session["credentials"] = refreshed_raw

    return creds


def _get_profile_email(creds: Credentials) -> str | None:
    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    return profile.get("emailAddress")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not _session_has_account():
            return redirect(url_for("login_page"))
        return view_func(*args, **kwargs)
    return wrapped


def api_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not _session_has_account():
            return jsonify({"error": "Not authenticated"}), 401
        return view_func(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login')
def login_page():
    if _session_has_account():
        return redirect(url_for("dashboard"))
    return render_template('login.html', error=request.args.get('error'))


@app.route('/auth/google')
def auth_google():
    flow = _build_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent',
    )
    session["oauth_state"] = state
    session["oauth_add_account"] = request.args.get("add_account") == "1"
    return redirect(authorization_url)


@app.route('/auth/callback')
def auth_callback():
    state = session.get("oauth_state")
    flow = _build_oauth_flow()
    flow.state = state
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as exc:
        return redirect(url_for("login_page", error=str(exc)))

    creds = flow.credentials
    try:
        user_email = _get_profile_email(creds)
    except Exception as exc:
        return redirect(url_for("login_page", error=f"Failed to load Gmail profile: {exc}"))

    if not user_email:
        return redirect(url_for("login_page", error="Failed to determine Gmail account email"))

    _set_active_account(user_email, _credentials_to_session(creds))
    session.pop("oauth_state", None)
    session.pop("oauth_add_account", None)
    return redirect(url_for("dashboard"))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route('/auth/switch-account', methods=['POST'])
@login_required
def switch_account():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    accounts = session.get("accounts", {})

    if not email or email not in accounts:
        return jsonify({"error": "Account not found"}), 404

    session["active_account_email"] = email
    session["credentials"] = accounts[email]
    session["user_email"] = email
    return jsonify({"status": "success", "active": email})


# ---------------------------------------------------------------------------
# Landing + Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
def landing():
    if _session_has_account():
        return redirect(url_for("dashboard"))
    return render_template('landing.html')


@app.route('/dashboard')
@login_required
def dashboard():
    user_email = session.get("active_account_email") or session.get("user_email")
    if not user_email:
        try:
            creds = _credentials_from_session()
            user_email = _get_profile_email(creds)
            if user_email:
                _set_active_account(user_email, session.get("credentials", _credentials_to_session(creds)))
        except Exception:
            user_email = None

    accounts = list((session.get("accounts") or {}).keys())
    if user_email and user_email not in accounts:
        accounts.append(user_email)

    return render_template('index.html', user_email=user_email, accounts=accounts)


# ---------------------------------------------------------------------------
# Gmail
# ---------------------------------------------------------------------------

def _decode_b64url(data: str) -> str:
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()


def _extract_message_content(payload: dict) -> tuple[str, str, list[dict]]:
    plain_parts = []
    html_parts = []
    attachments = []

    def walk(part):
        mime = part.get('mimeType', '')
        body = part.get('body', {})
        data = body.get('data')
        filename = (part.get("filename") or "").strip()

        if filename:
            attachments.append({
                "filename": filename,
                "mimeType": mime,
                "size": int(body.get("size", 0) or 0),
            })
        if data and mime == 'text/plain':
            plain_parts.append(_decode_b64url(data))
        elif data and mime == 'text/html':
            html_parts.append(_decode_b64url(data))
        for sub in part.get('parts', []) or []:
            walk(sub)

    walk(payload)

    if plain_parts:
        body_text = "\n".join(plain_parts).strip()
    elif html_parts:
        body_text = _strip_html("\n".join(html_parts))
    else:
        body_text = ""

    return body_text, "\n".join(html_parts).strip(), attachments


def _extract_urls(body_text: str, html_text: str) -> list[dict]:
    links = []
    seen = set()

    for href, anchor_text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_text or "", flags=re.IGNORECASE | re.DOTALL):
        actual_url = href.strip()
        try:
            parsed = urlparse(actual_url)
            domain = (parsed.hostname or "").lower()
        except ValueError:
            domain = ""
        display_text = _strip_html(anchor_text).strip()
        display_domain = _extract_display_domain(display_text)
        key = (actual_url, display_text)
        if not actual_url or key in seen:
            continue
        seen.add(key)
        links.append({
            "displayText": display_text or None,
            "actualUrl": actual_url,
            "domain": domain,
            "usesShortener": domain in URL_SHORTENERS,
            "displayDomainDiffers": bool(display_domain and domain and display_domain != domain),
            "looksSuspicious": bool(_domain_signals(domain)),
        })

    for url in re.findall(r'https?://[^\s<>"\')\]]+', body_text or "", flags=re.IGNORECASE):
        actual_url = url.strip()
        if not actual_url or any(link["actualUrl"] == actual_url for link in links):
            continue
        try:
            parsed = urlparse(actual_url)
            domain = (parsed.hostname or "").lower()
        except ValueError:
            domain = ""
        links.append({
            "displayText": None,
            "actualUrl": actual_url,
            "domain": domain,
            "usesShortener": domain in URL_SHORTENERS,
            "displayDomainDiffers": False,
            "looksSuspicious": bool(_domain_signals(domain)),
        })

    return links


def _summarize_links(links: list[dict]) -> dict:
    return {
        "count": len(links),
        "shortened": sum(1 for link in links if link["usesShortener"]),
        "displayMismatch": sum(1 for link in links if link["displayDomainDiffers"]),
        "suspiciousDomains": sum(1 for link in links if link["looksSuspicious"]),
    }


def _attachment_warnings(attachments: list[dict]) -> list[dict]:
    warnings = []
    for attachment in attachments:
        filename = attachment.get("filename", "")
        ext = os.path.splitext(filename)[1].lower()
        if ext in RISKY_ATTACHMENT_EXTENSIONS:
            warnings.append({
                "filename": filename,
                "extension": ext,
                "warning": f"Unusual attachment ({ext})",
            })
    return warnings


def _parse_auth_results(headers: dict) -> dict:
    raw = headers.get("Authentication-Results", "") or headers.get("authentication-results", "")
    result = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE"}
    for key in result:
        match = re.search(rf"{key}=(\w+)", raw, flags=re.IGNORECASE)
        if match:
            result[key] = match.group(1).upper()
    return result


def _sender_adjustment(sender_email: str, phishing_prob: float) -> tuple[float, list[str], str]:
    storage = _load_app_storage()
    normalized_sender = _clean_sender_email(sender_email)
    reasons = []
    sender_status = "neutral"
    adjusted = phishing_prob

    if normalized_sender and normalized_sender in storage["blocked_senders"]:
        adjusted = min(1.0, adjusted + 0.10)
        reasons.append("Blocked sender")
        sender_status = "blocked"
    elif normalized_sender and normalized_sender in storage["safe_senders"] and phishing_prob < 0.95:
        adjusted = max(0.0, adjusted - 0.12)
        reasons.append("Trusted sender")
        sender_status = "safe"

    return adjusted, reasons, sender_status


def _summarize_message(msg: dict) -> dict:
    payload = msg.get("payload", {})
    headers_list = payload.get("headers", [])
    headers = _normalize_header_map(headers_list)

    from_header = headers.get("From", "")
    sender_name, sender_email = email.utils.parseaddr(from_header)
    if not sender_name:
        sender_name = sender_email or "Unknown sender"

    body_text, html_text, attachments = _extract_message_content(payload)
    links = _extract_urls(body_text, html_text)
    attachment_warnings = _attachment_warnings(attachments)
    subject = headers.get("Subject", "(No Subject)")
    internal_date_ms = int(msg.get("internalDate", "0") or 0)
    timestamp = datetime.fromtimestamp(internal_date_ms / 1000, tz=timezone.utc).isoformat() if internal_date_ms else None

    return {
        "id": msg["id"],
        "senderName": sender_name,
        "senderEmail": sender_email,
        "subject": subject,
        "preview": (body_text or "").strip()[:200],
        "body": body_text,
        "timestamp": timestamp,
        "headers": headers,
        "links": links,
        "detectedLinksSummary": _summarize_links(links),
        "attachments": attachments,
        "attachmentWarnings": attachment_warnings,
        "authResults": _parse_auth_results(headers),
    }


def _fetch_and_analyze_emails(creds, query=None, page_token=None, max_results=20):
    """Fetches a page of Gmail messages and runs every one through the ML
    model. Shared by /api/emails (inbox + load-more) and /api/search so no
    fetch path can skip analysis."""
    service = build('gmail', 'v1', credentials=creds)
    list_kwargs = {"userId": "me", "maxResults": max_results}
    if query:
        list_kwargs["q"] = query
    if page_token:
        list_kwargs["pageToken"] = page_token

    listing = service.users().messages().list(**list_kwargs).execute()
    message_refs = listing.get('messages', [])

    results = []
    for ref in message_refs:
        msg = service.users().messages().get(userId='me', id=ref['id'], format='full').execute()
        email_data = _summarize_message(msg)

        try:
            analysis = _run_ml_analysis(email_data)
        except Exception:
            analysis = None

        email_data["analysis"] = analysis
        results.append(email_data)

    return results, listing.get('nextPageToken')


def _serialize_summary(email_data: dict) -> dict:
    analysis = email_data.get("analysis") or {}
    storage = _load_app_storage()
    feedback = storage["feedback"].get(email_data["id"])
    return {
        "id": email_data["id"],
        "senderName": email_data["senderName"],
        "senderEmail": email_data["senderEmail"],
        "subject": email_data["subject"],
        "date": email_data["timestamp"],
        "timestamp": email_data["timestamp"],
        "preview": email_data["preview"],
        "riskLevel": analysis.get("riskLevel", "Safe"),
        "riskScore": analysis.get("riskScore", 0),
        "confidenceScore": analysis.get("confidence", 0),
        "reasons": analysis.get("reasons", []),
        "detectedLinksSummary": email_data["detectedLinksSummary"],
        "attachmentWarnings": email_data["attachmentWarnings"],
        "feedback": feedback,
        "senderStatus": analysis.get("senderStatus", "neutral"),
    }


def _serialize_detail(email_data: dict) -> dict:
    summary = _serialize_summary(email_data)
    detail = dict(summary)
    detail.update({
        "body": email_data["body"],
        "headers": email_data["headers"],
        "links": email_data["links"],
        "attachments": email_data["attachments"],
        "analysis": email_data.get("analysis") or {},
        "authResults": email_data["authResults"],
    })
    return detail


def _fetch_message_detail(creds, message_id: str) -> dict:
    service = build('gmail', 'v1', credentials=creds)
    msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
    email_data = _summarize_message(msg)
    email_data["analysis"] = _run_ml_analysis(email_data)
    return email_data


@app.route('/api/emails')
@api_login_required
def api_emails():
    if ml_model is None or ml_vectorizer is None:
        return jsonify({"error": "Model not trained yet. Please run train_model.py first."}), 500

    creds = _credentials_from_session()
    try:
        emails, next_page_token = _fetch_and_analyze_emails(creds, page_token=request.args.get('pageToken'))
        return jsonify({"emails": [_serialize_summary(email_data) for email_data in emails], "nextPageToken": next_page_token})
    except Exception as exc:
        return jsonify({"error": f"Failed to fetch Gmail messages: {exc}"}), 500


@app.route('/api/search')
@api_login_required
def api_search():
    if ml_model is None or ml_vectorizer is None:
        return jsonify({"error": "Model not trained yet. Please run train_model.py first."}), 500

    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({"error": "Missing search query"}), 400

    creds = _credentials_from_session()
    try:
        emails, next_page_token = _fetch_and_analyze_emails(creds, query=query, page_token=request.args.get('pageToken'))
        return jsonify({"emails": [_serialize_summary(email_data) for email_data in emails], "nextPageToken": next_page_token})
    except Exception as exc:
        return jsonify({"error": f"Search failed: {exc}"}), 500


@app.route('/api/emails/<message_id>')
@api_login_required
def api_email_detail(message_id):
    if ml_model is None or ml_vectorizer is None:
        return jsonify({"error": "Model not trained yet. Please run train_model.py first."}), 500

    creds = _credentials_from_session()
    try:
        email_data = _fetch_message_detail(creds, message_id)
        return jsonify(_serialize_detail(email_data))
    except Exception as exc:
        return jsonify({"error": f"Failed to load email detail: {exc}"}), 500


@app.route('/api/delete-emails', methods=['POST'])
@api_login_required
def api_delete_emails():
    ids = (request.json or {}).get('ids', [])
    if not ids:
        return jsonify({"error": "No email ids provided"}), 400

    creds = _credentials_from_session()
    try:
        service = build('gmail', 'v1', credentials=creds)
        for message_id in ids:
            service.users().messages().trash(userId='me', id=message_id).execute()
        return jsonify({"status": "success", "deleted": len(ids)})
    except Exception as exc:
        return jsonify({"error": f"Failed to move emails to trash: {exc}"}), 500


@app.route('/api/feedback', methods=['POST'])
@api_login_required
def api_feedback():
    data = request.get_json(silent=True) or {}
    message_id = str(data.get("id", "")).strip()
    feedback = str(data.get("feedback", "")).strip()
    allowed = {"mark_safe", "mark_scam", "not_sure"}
    if not message_id or feedback not in allowed:
        return jsonify({"error": "Invalid feedback payload"}), 400

    storage = _load_app_storage()
    storage["feedback"][message_id] = feedback
    _save_app_storage(storage)
    return jsonify({"status": "success", "feedback": feedback})


@app.route('/api/sender-list', methods=['POST'])
@api_login_required
def api_sender_list():
    data = request.get_json(silent=True) or {}
    sender_email = _clean_sender_email(str(data.get("senderEmail", "")))
    action = str(data.get("action", "")).strip()

    if not sender_email or action not in {"safe", "block"}:
        return jsonify({"error": "Invalid sender-list payload"}), 400

    storage = _load_app_storage()
    storage["safe_senders"] = [value for value in storage["safe_senders"] if value != sender_email]
    storage["blocked_senders"] = [value for value in storage["blocked_senders"] if value != sender_email]
    target_key = "safe_senders" if action == "safe" else "blocked_senders"
    storage[target_key].append(sender_email)
    storage[target_key] = sorted(set(storage[target_key]))
    _save_app_storage(storage)
    return jsonify({"status": "success", "senderEmail": sender_email, "action": action})


# ---------------------------------------------------------------------------
# Local ML threat analysis (trained via train_model.py)
# ---------------------------------------------------------------------------

def _classify_risk(confidence: float) -> dict:
    for rule in RISK_RULES:
        if confidence >= rule["min_confidence"]:
            return {
                "riskLevel": rule["label"],
                "threatCategory": rule["category"],
            }
    return {"riskLevel": "Safe", "threatCategory": "SAFE"}


def _top_tfidf_terms(tfidf_vector, top_n: int = 5) -> list:
    """Words in THIS email's TF-IDF vector with the highest
    importance-weighted contribution, per the trained model's own feature
    weights (RandomForest feature_importances_, or |coef_| for linear models)."""
    if TFIDF_FEATURE_NAMES is None:
        return []
    importances = getattr(ml_model, "feature_importances_", None)
    if importances is None and hasattr(ml_model, "coef_"):
        importances = np.abs(ml_model.coef_[0])
    if importances is None:
        return []

    tfidf_arr = tfidf_vector.toarray()[0]
    n_tfidf = len(TFIDF_FEATURE_NAMES)
    contributions = tfidf_arr * importances[:n_tfidf]
    nonzero = np.where(tfidf_arr > 0)[0]
    ranked = sorted(nonzero, key=lambda i: contributions[i], reverse=True)
    terms = []
    for i in ranked:
        term = TFIDF_FEATURE_NAMES[i]
        if term is None:
            continue
        normalized = str(term).strip()
        if not normalized or normalized.lower() == "undefined":
            continue
        terms.append(normalized)
        if len(terms) >= top_n:
            break
    return terms


def _build_why_flagged(raw_text: str, features: np.ndarray, tfidf_vector, threat_category: str) -> list:
    """Plain-English reasoning bullets, built only from feature_extractor.py's
    own hand-crafted signals plus the model's own TF-IDF term weights - no
    external API. Only shown for SCAM_ALERT/SPAM per the product spec."""
    if threat_category not in ("SCAM_ALERT", "SPAM"):
        return []

    urgency_word_count, exclamation_count, all_caps_word_count, url_count, dollar_sign_count, email_length, has_attachment = features
    lower = raw_text.lower()
    bullets = []

    if urgency_word_count > 0:
        matched = [w for w in URGENCY_WORDS if w in lower][:2]
        example = f" (e.g. {', '.join(matched)})" if matched else ""
        bullets.append(f"Contains {int(urgency_word_count)} urgency phrase(s){example}")
    if url_count >= 2:
        bullets.append(f"Has {int(url_count)} link(s) - unusually high for a legitimate email")
    if all_caps_word_count >= 3:
        bullets.append(f"Written with {int(all_caps_word_count)} ALL-CAPS words - a common scam pressure tactic")
    if dollar_sign_count > 0:
        bullets.append(f"Contains {int(dollar_sign_count)} dollar-sign reference(s) - common in financial scam emails")
    if has_attachment:
        bullets.append("References an attachment that may carry a malicious payload")

    top_terms = _top_tfidf_terms(tfidf_vector)
    if top_terms:
        bullets.append("Top suspicious keywords detected: " + ", ".join(top_terms))

    return bullets


def _build_signal_analysis(raw_text: str, features: np.ndarray, risk_score: int) -> list:
    urgency_word_count, exclamation_count, all_caps_word_count, url_count, dollar_sign_count, email_length, has_attachment = features

    candidates = []
    if urgency_word_count > 0:
        candidates.append((urgency_word_count, f"High urgency language detected ({int(urgency_word_count)} urgency keyword match(es))"))
    if exclamation_count >= 2:
        candidates.append((exclamation_count, f"Excessive exclamation marks found ({int(exclamation_count)})"))
    if all_caps_word_count >= 2:
        candidates.append((all_caps_word_count, f"Excessive use of ALL-CAPS words ({int(all_caps_word_count)})"))
    if url_count > 0:
        candidates.append((url_count * 5, f"{int(url_count)} link(s) detected in the message body"))
    if dollar_sign_count > 0:
        candidates.append((dollar_sign_count * 3, f"Financial bait language detected ({int(dollar_sign_count)} dollar sign(s))"))
    if has_attachment:
        candidates.append((10, "References an attachment that may carry a malicious payload"))

    candidates.sort(key=lambda c: c[0], reverse=True)
    signals = [text for _, text in candidates[:3]]

    if not signals:
        signals.append("No strong urgency, link, or financial-bait signals detected in the message body")
    return signals


def _build_reasons(email_data: dict, adjusted_confidence: float, features: np.ndarray) -> list[str]:
    reasons = []
    urgency_word_count, _, all_caps_word_count, url_count, _, _, has_attachment = features
    sender_domain = _domain_from_value(email_data.get("senderEmail", ""))

    if email_data["detectedLinksSummary"]["displayMismatch"] > 0:
        reasons.append("Suspicious link")
    elif email_data["detectedLinksSummary"]["suspiciousDomains"] > 0:
        reasons.append("Possible spoofing")
    elif email_data["detectedLinksSummary"]["shortened"] > 0:
        reasons.append("Suspicious link")

    if urgency_word_count > 0 or all_caps_word_count >= 3:
        reasons.append("Urgent language")

    if _brand_name_mismatch(email_data.get("senderName", ""), sender_domain):
        reasons.append("Sender mismatch")

    if email_data["attachmentWarnings"] or has_attachment:
        reasons.append("Unusual attachment")

    auth_results = email_data.get("authResults", {})
    if any(auth_results.get(key) == "FAIL" for key in ("spf", "dkim", "dmarc")):
        reasons.append("Failed/weak authentication")

    if _domain_signals(sender_domain):
        reasons.append("Possible spoofing")

    if adjusted_confidence >= 0.95:
        reasons.append("Model confidence is high")

    unique = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return unique[:6] or ["No strong fraud signals detected"]


def _run_ml_analysis(email_data: dict) -> dict:
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    full_text = f"{subject}\n\n{body[:8000]}"
    cleaned = clean_text(full_text)
    tfidf_features = ml_vectorizer.transform([cleaned])
    handcrafted = extract_features(full_text)
    combined = hstack([tfidf_features, csr_matrix(handcrafted.reshape(1, -1))]).tocsr()

    probabilities = ml_model.predict_proba(combined)[0]
    phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
    adjusted_prob, sender_reasons, sender_status = _sender_adjustment(email_data.get("senderEmail", ""), phishing_prob)

    risk_score = max(0, min(100, int(round(adjusted_prob * 100))))
    confidence = int(round(adjusted_prob * 100))
    risk = _classify_risk(adjusted_prob)
    signal_analysis = _build_signal_analysis(full_text, handcrafted, risk_score)
    why_flagged = _build_why_flagged(full_text, handcrafted, tfidf_features, risk["threatCategory"])
    reasons = _build_reasons(email_data, adjusted_prob, handcrafted)
    for reason in sender_reasons:
        if reason not in reasons:
            reasons.append(reason)

    urgency_word_count = handcrafted[0]
    url_count = handcrafted[3]
    social_tactic = "URGENCY" if urgency_word_count >= 2 else "NONE"
    tactic_explanation = (
        f"Detected {int(urgency_word_count)} urgency-related keyword(s) commonly used to pressure recipients into acting without verifying the request."
        if social_tactic == "URGENCY"
        else "No strong social engineering language pattern detected by the model's hand-crafted features."
    )

    return {
        "riskScore": risk_score,
        "threatCategory": risk["threatCategory"],
        "riskLevel": risk["riskLevel"],
        "confidence": confidence,
        "signalAnalysis": signal_analysis,
        "whyFlagged": why_flagged,
        "reasons": reasons,
        "senderStatus": sender_status,
        "socialEngineeringTactic": social_tactic,
        "tacticExplanation": tactic_explanation,
        "confidenceBreakdown": {
            "urgencyLanguage": int(min(100, urgency_word_count * 20)),
            "domainMismatch": 100 if "Sender mismatch" in reasons else 0,
            "headerAnomalies": 100 if "Failed/weak authentication" in reasons or "Possible spoofing" in reasons else 0,
            "linkPatterns": int(min(100, url_count * 30)),
            "senderReputation": risk_score,
        },
    }


@app.route('/api/analyze', methods=['POST'])
@api_login_required
def api_analyze():
    if ml_model is None or ml_vectorizer is None:
        return jsonify({"status": "error", "error": "Model not trained yet. Please run train_model.py first."}), 500

    data = request.json or {}
    subject = str(data.get('subject', ''))
    body = str(data.get('body', ''))

    try:
        links = _extract_urls(body, "")
        email_data = {
            "id": "manual-analysis",
            "senderName": "",
            "senderEmail": "",
            "subject": subject,
            "preview": body[:200],
            "body": body,
            "timestamp": None,
            "headers": data.get("headers") or {},
            "links": links,
            "detectedLinksSummary": _summarize_links(links),
            "attachments": [],
            "attachmentWarnings": [],
            "authResults": _parse_auth_results(data.get("headers") or {}),
        }
        analysis = _run_ml_analysis(email_data)
        return jsonify({"status": "success", "analysis": analysis})
    except Exception as exc:
        return jsonify({"status": "error", "error": f"Local ML analysis failed: {exc}"}), 502


if __name__ == '__main__':
    port = int(os.getenv("PORT", 3000))
    app.run(host='0.0.0.0', port=port, debug=True)
