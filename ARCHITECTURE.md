# SENTRY — System Architecture

This document lists **every file/module needed** to turn the current HTML prototype into a real, working system, organized by layer. Owners are shown per the Execution Plan (see `EXECUTION_PLAN.md`).

---

## 1. High-level architecture

```
                         ┌─────────────────────────┐
                         │        FRONTEND          │
                         │   React dashboard (SPA)  │
                         └────────────┬─────────────┘
                                      │ REST/WebSocket
                                      ▼
                         ┌─────────────────────────┐
                         │        BACKEND API        │
                         │   Django / FastAPI        │
                         └──┬───────────┬───────────┘
                            │           │
              ┌─────────────┘           └─────────────┐
              ▼                                        ▼
   ┌────────────────────┐                  ┌─────────────────────────┐
   │  CORRELATION ENGINE │                  │  MEDIA INTEGRITY AGENT   │
   │  (attack-chain logic)│◄────evidence────►│  (S26 module, plugged in)│
   └──────────┬───────────┘                  └────────────┬────────────┘
              │                                            │
              ▼                                            ▼
   ┌────────────────────┐                  ┌─────────────────────────┐
   │   PLAYBOOK ENGINE    │                  │  SIGNATURE / DEEPFAKE     │
   │ (auto vs. manual)     │                  │  DETECTION MODELS         │
   └──────────┬───────────┘                  └────────────────────────┘
              ▼
   ┌────────────────────┐
   │      DATABASE        │
   │   PostgreSQL          │
   └────────────────────┘
```

**Core idea reflected in the architecture:** the Media Integrity Agent is a _plugin data source_ that feeds the same Correlation Engine and Playbook Engine as every other signal — it is not a parallel, separate backend.

---

## 2. Backend files (Owner: Biswanath, AI logic w/ Himani)

Using Django or FastAPI (pick one — FastAPI is lighter for a hackathon).

```
backend/
├── main.py                      # App entrypoint, mounts routers
├── requirements.txt
├── config.py                    # Env vars, secrets loader
│
├── models/
│   ├── alert.py                 # Alert model (id, severity, title, tags, resolved, chain[], etc.)
│   ├── evidence.py               # Individual evidence/signal (source, type, confidence)
│   ├── playbook_action.py        # Action model (label, risk_level, mode, status)
│   ├── credential.py             # Signing credential model (for media integrity)
│   └── audit_log.py              # Provenance/audit log entries
│
├── routers/  (or views/ if Django)
│   ├── alerts.py                 # GET /alerts, GET /alerts/{id}, POST /alerts (ingest)
│   ├── actions.py                 # POST /alerts/{id}/approve, POST /alerts/{id}/deny
│   ├── media_verify.py            # POST /media/verify (signature + deepfake check)
│   └── stream.py                   # WebSocket endpoint for live alert push
│
├── services/
│   ├── correlation_engine.py       # Core logic: groups raw signals into one alert w/ attack chain
│   ├── playbook_engine.py          # Decides auto-execute vs. needs-approval, by risk level
│   ├── media_integrity_service.py  # Wraps signature check + deepfake scan, returns evidence
│   ├── signature_verifier.py       # Cryptographic signature/hash verification logic
│   └── notification_service.py     # Sends alerts/toasts to frontend via WebSocket
│
├── ai/
│   ├── deepfake_detector.py         # ML model wrapper: audio/video authenticity scoring
│   ├── attack_chain_explainer.py    # (Optional LLM) turns raw correlated events into plain-English chain
│   └── confidence_scorer.py         # Combines multiple signal confidences into one score
│
├── db/
│   ├── database.py                  # DB connection/session
│   ├── schema.sql                   # Raw SQL schema (or use ORM migrations)
│   └── seed_data.py                 # Loads demo alerts (same as current HTML mock data)
│
└── tests/
    ├── test_correlation_engine.py
    ├── test_playbook_engine.py
    └── test_media_integrity.py
```

---

## 3. Frontend files (Owner: Bindusmita)

React app rebuilt from the current static HTML demo.

```
frontend/
├── package.json
├── src/
│   ├── App.jsx                       # Layout shell: topbar + 3-column grid
│   ├── index.jsx
│   ├── api/
│   │   ├── client.js                  # Axios/fetch wrapper
│   │   ├── alerts.js                   # getAlerts(), getAlert(id)
│   │   └── actions.js                  # approveAction(id), denyAction(id)
│   │
│   ├── components/
│   │   ├── TopBar.jsx                   # Brand, module chips, stats, simulate button
│   │   ├── AlertStream.jsx              # Left column: filterable alert list
│   │   ├── AlertItem.jsx                # Single alert row
│   │   ├── AttackChain.jsx              # Correlated chain visualization
│   │   ├── MediaVerificationPanel.jsx    # Signature/deepfake check display (S26 module UI)
│   │   ├── PlaybookPanel.jsx             # Recommended actions list
│   │   ├── ApprovalBar.jsx               # Approve/Deny controls
│   │   ├── SignerCard.jsx                 # Right column: credential detail
│   │   ├── ProvenanceLog.jsx              # Right column: audit trail
│   │   └── Toast.jsx                       # Notification popup
│   │
│   ├── hooks/
│   │   ├── useAlerts.js                    # Fetches + polls/subscribes to alerts
│   │   └── useWebSocket.js                  # Live connection to backend stream
│   │
│   ├── state/
│   │   └── alertsStore.js                   # Global state (Context or Zustand)
│   │
│   └── styles/
│       └── theme.css                         # Design tokens (colors, fonts — matches current prototype)
│
└── public/
    └── index.html
```

---

## 4. AI Agent files (Owner: Himani)

This is the "brain" that makes the merge (S26 + S27) actually work, separated so it's testable on its own.

```
ai-agent/
├── agent_config.yaml                 # Which models/thresholds to use
├── correlation/
│   ├── rules_engine.py                # Rule-based correlation (fast, explainable baseline)
│   └── ml_correlator.py               # Optional ML-based correlation for stretch goal
│
├── media_integrity/
│   ├── signature_check.py             # Verifies cryptographic signature against registry
│   ├── deepfake_scan.py               # Audio/video authenticity scoring (can start with a pretrained model or heuristic)
│   └── revocation_registry.py         # Checks if a credential has been revoked
│
├── playbook/
│   ├── risk_classifier.py             # Labels each action low-risk/high-risk
│   └── action_templates.json          # Predefined playbook actions per attack type
│
└── explainability/
    └── chain_explainer.py             # Generates the human-readable "Step 1 → Step 2..." narrative
```

**For the hackathon timeline:** start with `rules_engine.py` (if X + Y + Z happen within N minutes → one alert) and a heuristic/pretrained `deepfake_scan.py`. Real custom-trained ML is a stretch goal, not a requirement for a working demo.

---

## 5. Database schema (Owner: Biswanath)

Minimum tables needed:

- `alerts` — id, title, severity, status(open/resolved), created_at
- `evidence` — id, alert_id (FK), source_type(media/identity/network/endpoint/email), description, confidence
- `playbook_actions` — id, alert_id (FK), label, risk_level(low/high), mode(auto/manual/approved/denied)
- `credentials` — id, owner_name, credential_id, status(active/revoked)
- `audit_log` — id, alert_id (FK), timestamp, message

---

## 6. Infrastructure / other files (shared, mainly Himani for docs/security)

```
├── docker-compose.yml         # Spins up backend + frontend + postgres together
├── .env.example                # Template for secrets (DB url, API keys)
├── README.md                    # Setup instructions
├── EXPLANATION.md                # (this doc set)
├── ARCHITECTURE.md
├── WALKTHROUGH.md
├── EXECUTION_PLAN.md
├── ROADMAP.md
└── .github/workflows/ci.yml      # Optional: run tests automatically
```

---

## 7. How data flows for the flagship demo case (deepfake CFO video)

1. A video "arrives" (simulated ingestion in `alerts.py` POST endpoint, or a file upload for real demo).
2. `media_integrity_service.py` calls `signature_check.py` (fails — unsigned) and `deepfake_scan.py` (flags high risk). These become two **evidence** rows.
3. Meanwhile, `correlation_engine.py` also receives related email + identity evidence (sender domain lookalike, sent to finance staff).
4. `correlation_engine.py` groups all evidence under one `alert` row and builds the attack-chain order.
5. `playbook_engine.py` looks at the alert type and generates actions, marking low-risk ones `auto` (executed immediately) and high-impact ones `manual` (wait for approval).
6. Frontend receives this via WebSocket/poll, renders it in `AttackChain.jsx` + `MediaVerificationPanel.jsx` + `PlaybookPanel.jsx`.
7. Analyst clicks Approve/Deny → `actions.py` updates the DB → `audit_log` gets a new row → frontend updates live.
