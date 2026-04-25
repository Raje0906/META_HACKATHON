# SOC Simulator — Live Pitch Script
## Meta Hackathon 2026 | In-Person / Live Demo Presentation

---

## PART 1 — OPEN WITH THE PROBLEM (30 seconds, no laptop needed)

"Every second, thousands of cyberattacks are happening.
Companies have the tools to detect them. They just don't have enough humans to respond.

IBM measured this — the average breach takes **194 days** to detect and costs **$4.88 million**.
Not because the SIEM didn't flag it.
Because no one acted on the flag fast enough."

*[Pause two full seconds. Look at the judge. Then say:]*

"We built an environment to train AI agents to act on those flags.
Automatically. In real time. Across any company, any SIEM, any attack."

---

## PART 2 — WHAT MAKES YOU DIFFERENT (30 seconds)

"Every other team here probably built a static environment.
Fixed scenarios, fixed data, fixed schema.
You train on it, score well on it, deploy it —
and the first time a real attacker rotates their IP address, the agent fails.

**We built an adversary.**

Our Red Agent watches how the Blue Agent responds.
The moment it starts winning, the Red Agent mutates —
rotates IPs, changes credentials, escalates to obfuscation techniques from MITRE ATT&CK.

The agent can never memorize. It has to **reason**."

---

## PART 3 — LIVE DEMO (60–75 seconds, open the browser now)

*[Open: https://aditya9605-meta-hackathon-finale.hf.space/web]*

"This is our live environment. It's running on Hugging Face right now. Let me show you."

**Step 1 — Initialize**
- Select **EASY — Phishing Campaign** from the dropdown
- Click **Initialize Environment**

*[While it loads say:]*
"We have three difficulty levels. Easy, medium, hard. Each one maps to a real MITRE ATT&CK kill chain.
Right now I'm loading a phishing scenario — user gets a credential-harvesting email from Russia,
MFA gets bypassed, attacker logs in. Classic account takeover."

**Step 2 — Block the attacker**
- Action: `block_ip` / Target: `27.133.154.218` / Reason: `Malicious login from Russia`
- Click **Execute Action**

"I can see the event stream. The attacker IP is `27.133.154.218` — it sent the phishing email
and then used the stolen credentials 14 minutes later. First thing I do: block it."

**Step 3 — Flag the compromised user**
- Action: `flag_user` / Target: `alice.chen` / Reason: `Compromised via phishing`
- Click **Execute Action**

"Second: flag alice.chen. Her account was used by the attacker after MFA was bypassed."

**Step 4 — Evaluate**
- Click **Evaluate Episode**

*[Point at the score circle]*
"The grader is live. This isn't an LLM guessing — it's a deterministic rule-based verifier.
The agent either blocked the right IP or it didn't. No hallucination. No false credit."

---

## PART 4 — SHOW THE LEARNING (30 seconds, show the graph PNG or terminal)

*[Open: outputs/evals/red_vs_blue_curve.png — or show the terminal output]*

"We ran 50-episode baseline-vs-trained evaluations and publish raw metrics in `outputs/evals/scores.json`.

The important part is not one lucky score.
It is that trained policy outperforms the random baseline across tasks under adversarial mutation.

That is the difference between memorization and policy learning."

---

## PART 5 — PATRONUS BONUS (15 seconds, say it casually)

"One more thing — for the Patronus bonus.

We built a Schema Drift engine. Because Splunk calls it `source_ip`.
Sentinel calls it `remote_ip`. QRadar calls it something else.
Every AI SOC tool today is vendor-locked because of this.

Ours isn't. The agent learns what a field **means**, not what it's **called**."

---

## PART 6 — CLOSE (15 seconds, look up from laptop)

"The AI cybersecurity market is $30.9 billion, growing at 24% a year.
SOC analyst demand is projected to grow 332% by 2033.
The math doesn't work without automation at the triage layer.

We built the training ground for that automation.

Static environments train agents to memorize.
Adversarial environments train agents to reason.

That's SOC Simulator."

*[Stop. Don't add anything. Let the judge speak first.]*

---

## IF THEY ASK: "How is this different from fine-tuning on a cybersecurity dataset?"

> "Fine-tuning teaches the model what attacks looked like **in the past**.
> RL in an adversarial environment teaches the model how to respond to attacks **it's never seen**.
> One is memorization. The other is reasoning.
> The Red Agent guarantees the model never sees the same attack twice."

---

## DEMO CHEAT SHEET (keep this open on a second tab)

| Step | What to do |
|------|-----------|
| Browser | `https://aditya9605-meta-hackathon-finale.hf.space/web` |
| Initialize | EASY — Phishing Campaign → Initialize Environment |
| Action 1 | `block_ip` → `27.133.154.218` → Execute |
| Action 2 | `flag_user` → `alice.chen` → Execute |
| Evaluate | Click Evaluate Episode → point at score circle |
| Graph | Open `outputs/evals/red_vs_blue_curve.png` |
| W&B | `https://wandb.ai/rajeaditya999-/soc-simulator-grpo` |

---

## KEY NUMBERS (memorize these)

- **194 days** — average breach detection time (IBM)
- **$4.88M** — average breach cost (IBM)
- **$30.9B** — AI cybersecurity market size
- **24%** — annual market growth
- **332%** — projected SOC role growth by 2033
- **Baseline vs trained uplift** — use the latest value from `outputs/evals/scores.json`
- **50 episodes** — automated evaluation runs
