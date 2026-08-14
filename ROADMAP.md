# SENTRY — 1-Week Roadmap

A concrete day-by-day plan to take this from prototype to demo-ready working project, mapped to the Execution Plan stages and team roles.

---

## Day 1 — Foundation (Stages 1–4)

- **Aayushi:** Finish problem validation + competitor analysis (half-day each). Lock feature scope with MoSCoW list.
- **Bindusmita:** Start Figma wireframes based on the current HTML prototype layout (3-column SOC dashboard).
- **Biswanath:** Sketch system architecture (service boundaries) and draft DB schema — use `ARCHITECTURE.md` as the starting point.
- **Himani:** Research deepfake-detection approaches feasible in a week (pretrained model vs. heuristic-based scan); research signature/hash verification approach.
- **Yogeeta + Rounak:** Start pitch deck skeleton — problem slide, "why merge" slide, architecture slide placeholder.
  **End of day 1 checkpoint:** scope locked, wireframes started, architecture drafted.

---

## Day 2 — Scaffolding (Stages 5–7 begin)

- **Biswanath:** Set up backend repo (FastAPI/Django), Postgres, `docker-compose.yml`. Implement DB models (`alert`, `evidence`, `playbook_action`, `credential`, `audit_log`) and run migrations.
- **Bindusmita:** Set up React app scaffold. Port the existing static HTML/CSS from `soc_demo.html` into React components (`TopBar`, `AlertStream`, `AlertItem`) — get the UI rendering with the same mock data first, before wiring to a real API.
- **Himani:** Start `signature_check.py` (simple hash/signature verification against a mock credential registry) — this is achievable and demoable even without ML.
- **Aayushi:** Draft the judge Q&A prep doc; finalize MoSCoW feature list into a shareable one-pager.
  **End of day 2 checkpoint:** backend running locally with empty DB; frontend rendering the same demo alerts as before, but as React components.

---

## Day 3 — Core Logic (Stages 8–9)

- **Biswanath:** Build `correlation_engine.py` (rules-based: group evidence into one alert + build attack chain) and `playbook_engine.py` (risk classification: auto vs. manual). Wire `alerts.py` and `actions.py` API routes.
- **Himani:** Build `deepfake_scan.py` — start with a heuristic or a small pretrained model (e.g., an open-source audio/video authenticity classifier) that returns a risk score. Wire into `media_integrity_service.py`.
- **Bindusmita:** Connect frontend to real backend API for `GET /alerts` and `GET /alerts/{id}` — replace mock JS data with live fetch calls.
  **End of day 3 checkpoint:** real alerts flow from DB → API → frontend for at least the flagship deepfake-CFO scenario.

---

## Day 4 — Approval Flow + Media Panel (Stages 8–9 continued)

- **Biswanath:** Implement `POST /alerts/{id}/approve` and `/deny` — update playbook_action rows, write to `audit_log`.
- **Himani:** Finish `revocation_registry.py`; connect all three verification checks (signature, deepfake scan, revocation) into one evidence bundle per alert.
- **Bindusmita:** Build `MediaVerificationPanel.jsx`, `PlaybookPanel.jsx`, `ApprovalBar.jsx` fully wired to backend actions — clicking Approve/Deny should now persist to the real database.
- **Aayushi:** Run an informal internal walkthrough with the team acting as judges; note gaps.
  **End of day 4 checkpoint:** full Approve/Deny flow works end-to-end and survives a page refresh (proves it's real, not just UI state).

---

## Day 5 — Polish + Live Updates (Stages 10–12)

- **Biswanath + Bindusmita:** Add WebSocket (or polling) for live alert updates; performance pass — make sure the UI doesn't lag with 10+ alerts.
- **Himani:** Code review pass with Biswanath on correlation/playbook logic (focus: is anything mis-classified as auto that should require approval?). Start security audit: check auth on routes, input validation on any upload endpoint, no secrets committed.
- **Aayushi + whole team:** First full mock pitch + Q&A run-through (Stage 15 starts early, not just at the end).
- **Yogeeta + Rounak:** Pitch deck should be ~80% done by end of today.
  **End of day 5 checkpoint:** system feels stable and fast; first full mock demo completed with feedback captured.

---

## Day 6 — Testing, Docs, Refinement (Stages 13–14)

- **Himani:** Write/finish unit tests (`correlation_engine`, `playbook_engine`) and one full integration test (upload → evidence → alert → approval). Finalize documentation set (this file set, plus README + a simple architecture diagram image).
- **Biswanath:** Fix any bugs found in Day 5 mock demo. Finalize seed data so the demo always starts from a clean, impressive state.
- **Bindusmita:** Final UI polish — spacing, animations, empty/error states.
- **Aayushi:** Finalize judge Q&A prep sheet with likely tough questions (e.g., "how accurate is your deepfake detection really?" — have an honest, scoped answer ready).
  **End of day 6 checkpoint:** tests passing, docs complete, demo script rehearsed.

---

## Day 7 — Final Rehearsal & Buffer

- **Whole team:** Full run-through of the demo script from `WALKTHROUGH.md`, timed.
- **Whole team:** Fix only critical bugs found — resist adding new features this late.
- **Yogeeta + Rounak:** Final pitch deck lock, timing rehearsal.
- **Biswanath:** Confirm the whole stack runs from a clean checkout (`docker-compose up` from scratch) — this is the single most common last-minute failure at hackathons.
- **Buffer time:** keep the last few hours free for unexpected fixes, not new work.
  **End of day 7 checkpoint:** ready to demo.

---

## Risk notes (be realistic)

- **Real ML deepfake detection is hard to get accurate in a week.** It's fine — and honest — to use a heuristic or a pretrained open-source model and clearly label its limitations rather than overclaiming accuracy.
- **The single most important thing to protect is the end-to-end flow** (alert → evidence → correlation → approval → audit log) working live and reliably. If time runs short, cut polish before cutting this.
- **Keep the current HTML prototype (`soc_demo.html`) as a fallback demo** in case the live backend has issues during the actual presentation.
