# AI Phishing Website Detector — Flask App

A real, working phishing-detection dashboard. Unlike a static demo, this
version genuinely analyzes the URL you submit:

- **DNS resolution** — does the domain actually exist?
- **Live reachability** — does the server respond?
- **SSL certificate check** — is HTTPS actually valid?
- **Structural URL analysis** — IP address usage, `@` tricks, hyphen count,
  subdomain count, suspicious keywords, risky TLDs, punycode/homograph tricks,
  URL length

These are combined into a weighted score (rule-based, transparent — a stand-in
for a trained ML model) to produce a verdict, confidence %, risk level, and
scan time, exactly as specified in the project brief.

## Run it

```bash
cd phishing-flask-app
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Project structure

```
phishing-flask-app/
├── app.py                # Flask backend — real feature extraction + scoring
├── requirements.txt
├── templates/
│   └── index.html        # Jinja2 template (renders history + stats server-side)
└── static/
    ├── style.css          # Dark glassmorphism cybersecurity theme
    └── script.js          # Calls /predict via fetch, renders live results
```

## Upgrading to a trained ML model

Right now `score_features()` in `app.py` uses a transparent weighted rule
system. To swap in a real trained classifier (e.g. logistic regression /
random forest trained on the UCI Phishing Websites dataset):

1. Train a model offline using the same feature set as `extract_features()`
   returns (or adapt the extractor to match your model's expected inputs).
2. Save it with `joblib.dump(model, "phishing_model.pkl")`.
3. In `app.py`, load it once at startup (`model = joblib.load(...)`) and
   replace the body of `score_features()` with `model.predict_proba(...)`.

No other files need to change — the frontend just renders whatever
`label`, `confidence`, `risk_level`, and `features` the backend returns.

## Notes

- History and stats are stored in memory (`SCAN_HISTORY`, `STATS` in
  `app.py`) and reset when the server restarts. Swap in SQLite/Postgres for
  persistence across restarts.
- `app.run(debug=True)` is for local development only — use a production
  WSGI server (gunicorn/uWSGI) if you ever deploy this publicly.

## Credits

Created by **Poorni** — B.Tech Information Technology — AI & Machine
Learning Project
