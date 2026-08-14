# SENTRY — Walkthrough

A step-by-step guide to demoing (or using) the project, for teammates, judges, or new contributors.

---

## Part A — Running the current prototype (no setup needed)

1. Open `soc_demo.html` in any browser (double-click it, or drag into a browser tab). No server, no install — it's fully self-contained.
2. You'll see three columns:
   - **Left:** live alert stream
   - **Middle:** selected alert's detail (attack chain, verification, playbook)
   - **Right:** signing credential info + audit log

### Suggested demo script (2–3 minutes)

1. **Start on the flagship alert** (already selected on load): _"Unsigned CFO video urging urgent wire transfer."_
   - Point out the **Correlated Attack Chain**: video → impersonated sender → email delivery → known fraud pattern. Explain each step builds confidence.
   - Point out the **Media Integrity Verification** panel — this is the S26 functionality, shown as evidence, not a separate screen.
   - Point out the **Playbook**: two actions already auto-executed (quarantine, domain block), two waiting for approval (suspend account, freeze transfer).
   - Click **"Approve & Execute"** — watch the checkmarks update, a toast confirm the action, and the alert mark itself resolved.
2. **Switch to a non-media alert** (e.g., "Impossible-travel login") to show the _same_ engine handles ordinary SOC alerts identically — proving the merge is real, not cosmetic.
3. **Use the filter chips** — click "Media" to isolate deepfake/signature-type alerts, showing they live inside the same stream as everything else.
4. **Click "+ Simulate incoming alert"** to show the pipeline handling a brand-new event live, not just pre-scripted data.
5. **Close on the "Why this matters" note** in the right panel — this is your one-line pitch summary, already written into the product.

---

## Part B — Walkthrough once the real backend/frontend exists

_(Follow this once `ARCHITECTURE.md` is implemented — for now, Part A is the working demo.)_

1. `docker-compose up` — starts Postgres, backend API, and frontend dev server.
2. Backend seeds demo alerts from `seed_data.py` (same data as the current HTML mock).
3. Visit `http://localhost:3000` — same UI, now backed by a real database.
4. New alerts can be POSTed to `/alerts` (simulating an ingestion pipeline) or triggered via the "Simulate" button, which now calls the real API instead of injecting mock JS objects.
5. Approve/Deny buttons now call `POST /alerts/{id}/approve` or `/deny`, which write to `audit_log` in Postgres — so the audit trail survives a page refresh (unlike the current HTML-only version).
6. For the deepfake demo specifically: upload a short video/audio file through a demo upload form → it hits `/media/verify` → `signature_check.py` + `deepfake_scan.py` run for real → result becomes evidence in a new alert, live.

---

## Part C — What to say if a judge asks "is this real or just UI?"

Be direct: _"The interaction logic — correlation, playbook risk-gating, approval flow, audit logging — is fully working in-browser right now. The next layer is wiring this same logic to a real backend and real detection models, which is scoped in our architecture and roadmap docs. We prioritized proving the **workflow** works end-to-end before investing in training/hosting ML models under a hackathon deadline."_ This is an honest, defensible answer — most hackathon judges respect scoping decisions more than overclaiming.

---

## Part D — Files to have open/ready during the demo

- `soc_demo.html` — the live demo
- `EXPLANATION.md` — for backup Q&A on the "why"
- `ARCHITECTURE.md` — for backup Q&A on "what's next / is it real"
- Pitch deck (owned by Yogeeta + Rounak) — the actual narrative
