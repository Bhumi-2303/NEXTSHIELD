"""Phishing detection module.

Responsible for:
- Email header & body feature extraction (features.py)
- ML classification via LightGBM (model.py / train.py)
- Producing PhishingScanResult alerts (model.py)
- Exposing POST /api/v1/phishing/scan (router.py)

Architecture:
  train.py   (offline)  →  models/phishing_classifier.pkl
  router.py  (runtime)  →  model.py  →  features.py  →  PhishingScanResult
"""
