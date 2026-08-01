# 🛡️ NEXTSHIELD

**Explainable, Actionable Cybersecurity Threat Detection**

NEXTSHIELD is a threat detection platform with three pillars — **phishing classification**, **network anomaly detection**, and **guided incident‑response playbooks** — all mapped to [MITRE ATT&CK](https://attack.mitre.org/).

---

## 🏗️ Repository Structure

```
NEXTSHIELD/
├── backend/
│   ├── app/
│   │   ├── core/            # Config, logging, shared constants
│   │   │   ├── config.py        # pydantic-settings (env-driven)
│   │   │   ├── constants.py     # MITRETechnique enum, SeverityLevel enum
│   │   │   └── logging.py       # Structured logger factory
│   │   ├── schemas/         # Pydantic models — the shared contracts
│   │   │   ├── threat_alert.py      # ThreatAlert (base)
│   │   │   ├── shap_explanation.py  # SHAPExplanation + SHAPFeature
│   │   │   ├── playbook.py         # Playbook + PlaybookStep
│   │   │   ├── phishing.py         # PhishingScanResult(ThreatAlert)
│   │   │   └── anomaly.py          # NetworkAnomalyResult(ThreatAlert)
│   │   ├── modules/         # Feature modules (one per engineer)
│   │   │   ├── phishing/        # Email classification
│   │   │   ├── anomaly/         # Network flow anomaly detection
│   │   │   ├── playbook/        # IR playbook engine
│   │   │   └── explainability/  # SHAP-based XAI
│   │   ├── api/             # Route aggregation (imports from modules)
│   │   │   └── __init__.py      # Builds the api_router
│   │   └── main.py          # FastAPI app, CORS, health check
│   ├── requirements.txt
│   └── .env.example
├── frontend/                # Next.js app (TypeScript + Tailwind)
├── data/
│   ├── phishing/            # Email datasets
│   └── network/             # NetFlow / PCAP datasets
├── demo/                    # Live demo simulation scripts
└── README.md
```

---

## 🔌 How Modules Plug Into `main.py`

NEXTSHIELD uses a **router‑per‑module** pattern so that each engineer owns
an isolated package and merge conflicts are minimised.

```
main.py
  └── includes api_router          (from app.api)
        ├── phishing_router        (from app.modules.phishing.router)
        ├── anomaly_router         (from app.modules.anomaly.router)
        ├── playbook_router        (from app.modules.playbook.router)
        └── explainability_router  (from app.modules.explainability.router)
```

### Adding a new module

1. Create `backend/app/modules/<your_module>/`
2. Add `router.py` with a `router = APIRouter(prefix="/your-module")`
3. Import and include it in `backend/app/api/__init__.py`:
   ```python
   from ..modules.your_module.router import router as your_module_router
   api_router.include_router(your_module_router)
   ```
4. **Done** — no changes to `main.py` required.

---

## 📜 Shared Contracts (Pydantic Schemas)

All inter‑module data flows through the models in `backend/app/schemas/`.
This ensures every API response, dashboard card, and playbook lookup speaks
the same language.

| Schema | File | Purpose |
|---|---|---|
| `ThreatAlert` | `threat_alert.py` | Base alert envelope — id, timestamp, severity, MITRE ID, confidence, SHAP explanation, recommended playbook |
| `SHAPExplanation` | `shap_explanation.py` | XAI output: top features with SHAP values and human‑readable reasons |
| `Playbook` | `playbook.py` | Incident‑response runbook: ordered steps, automatable flags, ETA |
| `PhishingScanResult` | `phishing.py` | Extends `ThreatAlert` with email‑specific fields (SPF, DKIM, DMARC, domain age, urgency score) |
| `NetworkAnomalyResult` | `anomaly.py` | Extends `ThreatAlert` with network‑flow fields (IPs, protocol, flow duration, zero‑day flag) |

### MITRE ATT&CK Techniques (enum)

| ID | Name |
|---|---|
| T1566 | Phishing |
| T1071 | Application Layer Protocol (C2) |
| T1046 | Network Service Discovery |
| T1078 | Valid Accounts |
| T1499 | Endpoint Denial of Service |

---

## 🚀 Quickstart

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # customise if needed
uvicorn app.main:app --reload --port 8000
```

Visit **http://localhost:8000/docs** for the interactive Swagger UI.
Health check: `GET http://localhost:8000/health`

### Frontend

```bash
cd frontend
npx -y create-next-app@latest ./ --typescript --tailwind --app --eslint --src-dir --no-import-alias
npm run dev
```

The Next.js dev server starts on **http://localhost:3000** and is already
CORS‑allowed by the backend.

---

## 🧪 API Endpoints (v1)

| Method | Path | Module | Status |
|---|---|---|---|
| `GET` | `/health` | System | ✅ Live |
| `POST` | `/api/v1/phishing/scan` | Phishing | 🔧 Stub |
| `POST` | `/api/v1/anomaly/detect` | Anomaly | 🔧 Stub |
| `GET` | `/api/v1/playbooks/` | Playbook | 🔧 Stub |
| `GET` | `/api/v1/playbooks/{id}` | Playbook | 🔧 Stub |
| `POST` | `/api/v1/explain/` | XAI | 🔧 Stub |

---

## 👥 Parallel Development Guide

| Engineer | Owns | Works in | Imports from |
|---|---|---|---|
| **A** | Phishing classifier | `modules/phishing/` | `schemas.PhishingScanResult` |
| **B** | Anomaly detector | `modules/anomaly/` | `schemas.NetworkAnomalyResult` |
| **C** | Playbook engine | `modules/playbook/` | `schemas.Playbook` |
| **D** | Explainability (SHAP) | `modules/explainability/` | `schemas.SHAPExplanation`, `schemas.ThreatAlert` |
| **E** | Frontend dashboard | `frontend/` | Backend REST API |

Each engineer works in their own directory. The shared contracts in
`schemas/` are the **only** coupling point — agree on schema changes in PRs.

---

## 📝 License

MIT — Hackathon project.
