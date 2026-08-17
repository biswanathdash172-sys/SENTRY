# SENTRY — Human-Governed Autonomous SOC

### (with Integrated Media & Identity Integrity Detection)

A complete, beginner-friendly explanation of what this project is, why it exists, and how it works.

---

## 1. What problem are we solving?

Two problems, merged into one project:

**Problem A (core — SOAIDEATHON-S3):** Companies and campuses get attacked constantly — phishing emails, stolen logins, ransomware, weird network traffic. Security teams (called a "SOC" — Security Operations Center) get flooded with alerts from ten different tools that don't talk to each other. Analysts waste hours manually connecting the dots between "this email looked weird" and "this login was from another country" before they even understand what's happening — by which time the attacker may have already succeeded.

**Problem B (merged in — SOAIDEATHON-S26):** Separately, deepfake videos, cloned voices, and faked "official" messages are now being used to trick employees — e.g., a fake video of the CFO asking someone to urgently wire money. Most companies have no way to verify whether an official-looking video, voice message, or notice is genuinely from who it claims to be.

**Our insight:** Problem B is just a _new kind of evidence_ that Problem A's system should already know how to handle. A fake CFO video and a phishing email are the same category of attack (impersonation → urgency → bypass normal process) — they just arrive through a different channel. So instead of building two separate tools, we build **one SOC platform where "is this media authentic?" is simply one more signal the correlation engine understands.**

---

## 2. What does the finished product do? (In plain English)

Imagine a control-room screen for a security analyst:

1. **Alerts stream in** from many sources: email, network, employee logins, endpoints (laptops/servers), and now also "media integrity" (videos, voice messages, signed documents).
2. **The system automatically connects the dots.** For example: "an unsigned video claiming to be the CFO" + "a lookalike email domain" + "sent to 3 finance staff" = these three separate weak signals become one strong, explained alert: _"This is very likely a deepfake-powered wire-fraud attempt."_
3. **It explains itself.** Every alert shows a step-by-step "attack chain" with confidence scores, not just a black-box score. A beginner (or a judge) can read it top to bottom and understand why the system is worried.
4. **It acts — but carefully.** Low-risk, reversible actions (quarantine an email, block a number, isolate a laptop from the network) happen automatically. High-impact, hard-to-reverse actions (suspend an account, freeze a wire transfer) always **wait for a human to click Approve or Deny.** This is the "human-governed" part — the AI never takes the biggest risks by itself.
5. **Everything is logged.** A provenance log records exactly what happened, when, and why — useful for audits and for proving the system didn't act recklessly.

---

## 3. Why is this "AI" and not just a dashboard?

- The **correlation engine** uses pattern-matching / ML logic to decide that several unrelated-looking events are actually one attack — this is the "connect the dots" intelligence.
- The **media integrity module** uses signal-processing / ML models to judge whether a video or voice sample is likely synthetic (deepfake detection) and checks cryptographic signatures to see if content is provably authentic.
- The **playbook engine** ranks recommended actions by risk and explains its reasoning — this is what makes it "explainable AI" rather than a black box.

---

## 4. The two original problem statements, and how they merged

|                             | SOAIDEATHON-S27 (core)                                                                                 | SOAIDEATHON-S26 (merged in)                                                        |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Name                        | Human-Governed Autonomous SOC                                                                          | Deepfake-Resistant Provenance & Verification                                       |
| What it normally does alone | Correlates logs/telemetry, recommends recovery playbooks, needs human approval for high-impact actions | Signs official communications, verifies authenticity, detects manipulation         |
| How it's merged here        | This is the whole app                                                                                  | Folded in as **one more alert/evidence source** inside the SOC, not a separate app |

We chose to keep S27 as the primary architecture because it already had the right shape: correlate → explain → recommend → require approval. S26 just needed to plug into that shape as a new _type of evidence_, which is exactly what we did.

---

## 5. What's already built (prototype)

A working **interactive demo** (`soc_demo.html`) that includes:

- A live alert stream with filters (All / Identity / Network / Media / Endpoint)
- A correlated "attack chain" view per alert
- A media-integrity verification panel (signature check, deepfake-likelihood scan, revocation check)
- A recommended playbook with auto-executed vs. "needs your approval" actions
- Working Approve/Deny buttons that update state live
- A "Simulate incoming alert" button to demo the live pipeline
- A provenance/audit log
  This prototype currently runs on **fake/mock data in the browser** — no real backend, no real ML models yet. The next step is turning this into a real, working system — see `ARCHITECTURE.md` for what needs to be built, and `ROADMAP.md` for how to build it in a week.

---

## 6. Key terms, explained simply

| Term                         | Plain-English meaning                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------- |
| SOC                          | "Security Operations Center" — the team/system that watches for attacks             |
| Correlation engine           | Software that looks at many small clues and figures out they're part of one attack  |
| Playbook                     | A pre-approved list of response steps for a given type of attack                    |
| Human-in-the-loop            | The AI can suggest and do small things, but a person must approve big/risky actions |
| Deepfake                     | AI-generated fake video/audio that impersonates a real person                       |
| Provenance                   | Proof of where something came from and that it hasn't been tampered with            |
| Signing credential           | A cryptographic "signature" that proves a message really came from who it claims    |
| Audit trail / provenance log | A permanent record of what the system did and why, for later review                 |

---

## 7. Team roles for this project (from the Execution Plan)

Based on the team's execution plan, here is what each person owns for THIS specific project:

- **Biswanath (Team Leader)** — Owns the **System Architecture** (deciding how the backend, correlation engine, and media-verification module fit together as services), the **Database Design** (schema for alerts, playbooks, evidence, users), core **Backend Development** (models, API routes, the correlation/playbook logic), and shares **Performance Optimization** with Bindusmita (making sure the dashboard stays fast even with many live alerts).
- **Aayushi, Yogeeta, and Rounak (jointly)** — Own **Research & Problem Validation** (proving SOC alert fatigue and deepfake fraud are real, scoped problems worth solving), **Competitor Analysis** (what existing SOC/SIEM tools and deepfake-detection tools do, and why merging them is our edge), **Product Management** (deciding which features are must-have vs. nice-to-have for the demo, using MoSCoW prioritization), lead the **Hackathon Judge Simulation** (running mock Q&A with the team before the real pitch), and own the **Pitch Deck & Script / Pitch Video**, working in parallel from day one so the story ("why merge S26+S27, what problem it solves, why it's better than existing tools") is ready alongside the product, not rushed at the end. These three tasks (previously split as Aayushi-only research/product work and Yogeeta+Rounak-only pitch work) are now combined and shared across all three of them.
- **Bindusmita** — Owns **UI/UX Design** (the Figma/wireframe version of the dashboard before code is written) and **Frontend Generation** (porting the working static-HTML dashboard — alert stream, attack-chain view, verification panel, playbook, approval buttons — into real React components; not yet started, see README.md's "Current build status" note), and shares **Performance Optimization** with Biswanath on the frontend side (fast rendering, no lag when alerts stream in).
- **Himani** — Owns **AI Feature Integration** (the actual ML/LLM logic: the correlation scoring, the deepfake-likelihood scan, and any LLM used to generate plain-English explanations of the attack chain), **Code Review & Refactoring** (with Biswanath, keeping the codebase clean and bug-free), **Security Audit** (making sure authentication, input validation, and secrets are handled properly — especially important since this is literally a security product), **Testing & QA** (unit tests, integration tests, and running full demo dry-runs before presenting), and **Documentation & Flowcharts** (README, architecture diagrams — this set of files is part of that responsibility).
- **Biswanath (Team Leader)** — In addition to owning System Architecture, Database Design, and core Backend Development (see above), coordinates across all workstreams as team lead — final call on scope trade-offs and demo-readiness.
  See `EXECUTION_PLAN.md` for the full stage-by-stage breakdown and `ROADMAP.md` for how these roles map onto a 7-day build schedule.
