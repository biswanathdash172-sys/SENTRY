# SENTRY — Human-Governed Autonomous SOC
### (with Integrated Media & Identity Integrity Detection)

SENTRY is a unified Security Operations Center (SOC) platform designed to solve two major enterprise security challenges simultaneously: SOC analyst alert fatigue and deepfake-driven identity fraud[cite: 10]. 

Rather than treating media authenticity as a separate problem, SENTRY integrates deepfake detection and cryptographic signature verification as native signals within a standard SOC correlation engine[cite: 10]. 

---

## 📖 The Core Philosophy (How it Works)
SENTRY operates on the principle that a deepfake CFO video and a phishing email are fundamentally the same category of attack (impersonation → urgency → process bypass)[cite: 10]. 

*   **Multi-Source Ingestion:** The system streams alerts from various sources, including email, network, employee logins, endpoints, and media integrity modules (videos, voice messages, signed documents)[cite: 10].
*   **AI Pattern Correlation:** The correlation engine automatically connects disparate events[cite: 10]. For example, it links an unsigned video claiming to be the CFO, a lookalike email domain, and targeted finance staff into one high-confidence alert[cite: 10].
*   **Explainable AI (XAI):** Every alert generates a step-by-step "attack chain" with confidence scores to explain exactly why the system flagged the event[cite: 10].
*   **Human-Governed Response:** SENTRY utilizes a Playbook Engine that acts carefully based on risk[cite: 10]. Low-risk actions (quarantining an email) auto-execute, while high-impact actions (freezing wire transfers) always wait for human approval[cite: 10].
*   **Immutable Provenance:** An audit log records exactly what happened, when, and why for compliance and review[cite: 10].

---

## 🏗️ System Architecture

The architecture relies on the concept that the **Media Integrity Agent is a plugin data source** feeding the same engines as other network signals, rather than operating as a parallel, isolated backend.

```text
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
