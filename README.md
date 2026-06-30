# GuardMail AI - Email Threat Analysis Console

A Flask dashboard that signs in with Google, pulls your latest Gmail messages
through the Gmail API, and analyzes them with a locally trained scikit-learn
model. Header forensics, spoof checks, link scanning, sender controls, and
feedback all stay inside the app.

## 1. Prerequisites

- Python 3.10+
- A Google Cloud project with the Gmail API enabled
- An OAuth client (Web application) whose redirect URI is
  `http://localhost:3000/auth/callback`

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

Optional virtualenv setup:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Configure `.env`

Create your own local `.env` from `.env.example`.

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback
SESSION_SECRET=replace_with_a_long_random_string
PORT=3000
```

Do not commit `.env`, OAuth secrets, access tokens, or private config.

## 4. Training the model

The app loads `model.pkl.gz` and `vectorizer.pkl` at startup, so train them once
before running the dashboard.

1. Put the Kaggle CSV datasets in the project root.
2. Run:

```bash
python train_model.py
```

3. Confirm these files were created:
   - `model.pkl.gz`
   - `vectorizer.pkl`
   - `evaluation_report.json`

`train_model.py` prints classification metrics for both candidate models and
saves the evaluation summary as JSON.

## 5. Run the app

```bash
python api/index.py
```

Open [http://localhost:3000](http://localhost:3000).

After sign-in:
- the first 20 inbox emails are fetched and analyzed automatically
- the inbox API returns summary fields only by default
- full email bodies and raw headers are fetched only when you explicitly open
  an email
- suspicious emails can only be moved to Gmail trash after confirmation

If you signed in before the trash flow was added, sign out and back in once so
the session includes the `gmail.modify` scope.

## Notes

- `.env`, `model.pkl`, `vectorizer.pkl`, `evaluation_report.json`, and
  `app_storage.json` are gitignored local files.
- OAuth tokens stay in the signed Flask session cookie, not in a server-side
  database.
- User feedback plus safe/block sender lists are stored locally in
  `app_storage.json`.
- `feature_extractor.py` is shared by both training and runtime inference so
  feature extraction stays consistent.
