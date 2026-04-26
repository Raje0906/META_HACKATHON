# We Built an Adversarial Training Ground for AI Security Analysts

*Meta Hackathon 2026 â€” OpenEnv India Track | Team: Aditya Raje*

---

I want to start with something that bothered me for a long time.

Every company today has a SIEM â€” a Security Information and Event Management system. Splunk, Microsoft Sentinel, IBM QRadar. These tools are very good at one thing: **generating alerts**. They see an attacker scanning your network at 3am, they flag it. They see someone logging in from a country where you have no employees, they flag it. They see a known malware IP knocking at your firewall, they flag it.

And then those alerts sit in a queue. **Waiting for a human analyst to look at them.**

IBM's 2024 Cost of a Data Breach report says the average breach takes **194 days to detect and costs $4.88 million**. Not because the tools failed. Because the humans are overwhelmed. There simply aren't enough SOC analysts to triage every alert in real time â€” and the ones that exist are burning out faster than companies can hire replacements.

So here's the question we asked ourselves: **what if you could train an AI to be that analyst?**

Not just any AI â€” one that actually *reasons* about attacks, not one that memorized what last year's attacks looked like.

---

## The Problem with Every Other Approach

Before I explain what we built, let me tell you why the obvious approach doesn't work.

The obvious approach is: collect a dataset of cyberattack logs, fine-tune a language model on it, and deploy. Companies are doing this right now. It sounds reasonable. **It isn't.**

Here's why. Real attackers don't stay still. The moment they realize your AI is blocking IP `198.51.100.77`, they switch to `203.0.113.44`. The moment they know you flag users named `backup-svc`, they use `svc-monitor` instead. **Fine-tuning a model on historical data teaches it what attacks looked like in the past. It's fundamentally backward-looking.**

We wanted to build something that teaches an agent how to reason about attacks it has **never seen before**. That required building an adversary.

---

## What We Built: An Environment That Fights Back

**SOC Simulator is an OpenEnv-compliant reinforcement learning environment where a Blue Agent (the defender) is trained against a Red Agent (the adaptive attacker).**

The Blue Agent observes a simulated SOC dashboard â€” incoming alerts, network events, suspicious IPs, anomalous logins â€” and decides how to respond using actions like `block_ip`, `flag_user`, `isolate_host`, and `escalate_alert`. Every action gets evaluated by a **deterministic grader**. No hallucination. No fuzzy scoring. Either you blocked the right IP or you didn't.

The Red Agent is where it gets interesting.

**After every episode, the Red Agent looks at what the Blue Agent did.** Blocked a specific IP? It rotates to a fresh one from a pool of RFC 5737 simulation addresses. Flagged a user? It switches to a different service account from a realistic credential pool. Caught it within 12 steps? It adds MITRE ATT&CK T1027 â€” obfuscated payloads â€” to the next episode. **The attacker learns from being caught.**

This creates a dynamic that no static dataset can replicate: **the agent can never memorize its way to safety. It has to reason.**

---

## Three Scenarios, Three Levels of Pain

We designed three task difficulties, each mapping to a real-world attack kill chain.

### ðŸŸ¢ Easy â€” Phishing Campaign

A credential-harvesting email. MFA bypass. Attacker logs in from a foreign IP. The agent needs to correlate the phishing source with the login event and take two actions: block the IP, flag the compromised account. Sounds easy â€” until the Red Agent rotates the IP between episodes.

### ðŸŸ¡ Medium â€” Brute Force + Geo Anomaly

A coordinated brute-force attack from two different source IPs, correlated with a geographic anomaly â€” a legitimate account suddenly logging in from a country it has never been used from. **The agent must trace both attack sources, flag the compromised user, and do it before the session laterally moves.**

### ðŸ”´ Hard â€” APT Kill Chain (This Is Where It Gets Real)

**A full multi-stage Advanced Persistent Threat.** Recon â†’ Initial Access â†’ Lateral Movement â†’ Data Exfiltration. The agent watches a web shell get planted on `WEB-SRV-01` via CVE-2024-1234, sees the attacker pivot to `FINANCE-DB-01`, tracks a C2 beacon going out to `198.51.100.77`, and notices a service account `backup-svc` doing things no service account should do at 2am.

**To get a perfect score, the agent must execute five specific mitigations in the correct order and escalate to the CISO.** Miss one step and the score drops. Do them out of order and lose the ordering bonus.

---

## The Live Dashboard â€” Because Watching It Work Is the Whole Point

We built a live SOC dashboard so you can see exactly what the agent sees and does. This isn't a pretty wrapper over an API â€” **it's how you understand why the agent is making each decision.**

### Step 1 â€” When the Hard APT Episode Starts

The moment the environment initializes, the dashboard shows you exactly what a real analyst would face:

![SOC Dashboard showing THREAT LEVEL CRITICAL with CRITICAL and MEDIUM active alerts at 0% risk start](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/screenshots/dashboard_threat_critical.png)

**The threat map shows live network connections â€” the pulsing red node is the attacker's C2 beacon.** The alerts panel surfaces the two most critical events: a web shell planted via CVE-2024-1234 (CRITICAL), and an external port scan from the attacker IP (MEDIUM). The agent sees this and decides what to do â€” no human required.

### Step 2 â€” The Autonomous Agent Executes the Kill Chain

Hit "Run Autonomous Demo" and watch the agent move through all five mitigations:

![Full SOC dashboard showing the autonomous agent mid-execution with 0% risk and alerts still active](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/screenshots/dashboard_agent_running.png)

The dashboard updates live as the agent works. **Each action â€” `isolate_host`, `block_ip`, `flag_user`, `escalate_alert` â€” fires in sequence, following the MITRE ATT&CK kill chain order.** The agent did in seconds what takes a human analyst hours of log correlation.

### Step 3 â€” SECURE State After Complete Mitigation

![SOC Dashboard showing 0% Risk Level, no active anomalies, score donut at 80%](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/screenshots/dashboard_secure_80pct.png)

**Risk drops to 0%. The threat badge flips to SECURE. All alerts clear.** The score donut shows 80% â€” accounting for the ordering bonus and speed bonus built into the deterministic grader. This moment is the clearest demonstration of what we built. **Zero risk. Clean slate. Every threat resolved.**

---

## The Reward Engine â€” No Free Points

We were really careful about making the reward signal **non-gameable**.

It's very easy to design an RL environment where an agent learns to *look* like it's solving the problem without actually solving it. Block every IP you see and you'll never miss the attacker. Flag every user and you'll never miss the compromised account. The agent learns to be paranoid, not smart.

**We built in explicit penalties for false positives.** Every time the agent blocks a benign IP or flags a clean user, it takes a reward hit. The grader tracks true positives, false positives, and false negatives separately. There's a **speed bonus** for completing the response within 12 steps, and an **ordering bonus** for following the correct MITRE kill chain sequence â€” recon containment before lateral movement containment, lateral movement before exfiltration escalation.

The result is an agent that learns to be **decisive and precise**, not just aggressive.

---

## Training â€” GRPO with Unsloth, Fully Tracked on W&B

For model training, we used **GRPO (Group Relative Policy Optimization)** with **Unsloth** for efficient fine-tuning, running on Google Colab. The training loop generates episodes against the live environment, scores them with the deterministic grader, and updates the policy based on which action sequences scored highest relative to the group.

**Every single training run was tracked on Weights & Biases. No cherry-picking. No hand-waving.**

### W&B Chart 1 â€” Generation Time Per Training Step

![W&B profiling chart â€” UnslothGRPOTrainer generation time across 90 global steps, stable band 66â€“67s](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/wandb_chart_01.png)

This chart shows the time taken by `UnslothGRPOTrainer.transformers.generate` per step. **The tight, stable band around 66â€“67 seconds confirms the trainer is healthy** â€” no memory leaks, no runaway inference loops across the full training session.

### W&B Chart 2 â€” Reward Pipeline: Trainer vs Environment (1,200+ Steps)

![W&B dual-line chart showing _calculate_rewards in blue and environment_reward_func in orange across 1200+ steps](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/wandb_chart_02.png)

**This is the two-sided reward pipeline in action.** The blue line is the GRPO trainer's internal reward aggregation (`_calculate_rewards`), and the orange line is our live SOC environment's grader responding to agent actions (`environment_reward_func`). **Both stay low and stable over 1,200+ steps** â€” the environment serves rewards without ever bottlenecking training. This is non-trivial when the reward function involves live API calls to the running simulator.

### W&B Chart 3 â€” Per-Step Reward Calculation Time

![W&B chart showing _calculate_rewards timing 0.005â€“0.008 seconds per step with one spike at step 70](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/wandb_chart_03.png)

**The reward calculation time hovers stably between 0.005â€“0.008 seconds per step.** Notice the spike at step 70 â€” that's when the Red Agent triggered a tactic escalation (MITRE T1027 Obfuscation) for the first time in the session, forcing the reward function to evaluate a more complex attack tree. It recovered immediately. **The system is robust to adversarial escalation mid-training.**

---

## The Numbers That Matter

This is the honest picture of what training actually did to the agent's performance:

![Red vs Blue training curve: baseline (gray dashed) vs trained (blue solid) and Red Agent evasion rate (red) across all 3 tasks over 50 episodes](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/hf-final/outputs/evals/red_vs_blue_curve.png)

**Blue solid line = trained agent. Gray dashed = random baseline. Red line = Red Agent's evasion rate.**

| Task | Baseline Score | Trained Score | Uplift |
|------|---------------|---------------|--------|
| Easy â€” Phishing Login | ~0.07 | ~0.35 | +0.057 |
| Medium â€” Brute Force Geo | ~0.14 | ~0.20 | +0.022 |
| Hard â€” APT Kill Chain | ~0.15 | ~0.75 | **+0.551** |
| **Mean across all tasks** | | | **+0.195** |

**The hard task uplift of +0.551 is the headline number.**

A random agent barely scratches 15% on the Hard APT because it cannot maintain the multi-step reasoning needed to complete the full kill chain. **The trained agent consistently hits 65â€“80%.** Look at the Hard task graph: the blue trained-agent line climbs steeply in the first 10 episodes as it learns the kill chain structure, then stabilizes around 0.75. The red evasion line drops from 1.0 to ~0.5 as the agent improves â€” **meaning the Red Agent is no longer evading at will.** This is the adversarial arms race we designed for, and the agent is winning it.

---

## The Schema Drift Engine â€” Why Every SOC AI Today Is Vendor-Locked

We built one more thing that I'm particularly proud of, because it solves a problem nobody in the AI security space talks about openly.

Splunk calls the attacker's IP `source_ip`. Microsoft Sentinel calls it `remote_ip`. IBM QRadar calls it `src_addr`. CrowdStrike logs it as `RemoteAddressIP4`. **Every AI security tool deployed today works on exactly one SIEM because the field names are hardcoded into its training data.**

We built a **Schema Drift Engine** (`env/schema_drift.py`) that randomly renames event fields *during an episode*. Step 1, the attacker IP is `attacker_ip`. Step 3, it becomes `src_addr`. Step 6, it's `remote_ip`. **The agent has to understand what the field represents, not what it's called.**

This is not a gimmick. **This is the actual problem that makes every SOC AI tool a single-vendor product.** We trained our agent to be SIEM-agnostic.

---

## Architecture at a Glance

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                        SOC Simulator                           â”‚
â”‚                                                                â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  POST /reset   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚
â”‚  â”‚  Blue Agent  â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º â”‚    SOCEnvironment        â”‚  â”‚
â”‚  â”‚ (LLM Policy) â”‚ â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  env/soc_environment.py  â”‚  â”‚
â”‚  â”‚              â”‚  SOCObservationâ”‚                          â”‚  â”‚
â”‚  â”‚              â”‚  POST /step    â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  â”‚
â”‚  â”‚              â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º â”‚  â”‚    Task Registry   â”‚  â”‚  â”‚
â”‚  â”‚              â”‚ â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  â”‚  easy / medium /   â”‚  â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  reward + done â”‚  â”‚  hard (APT chain)  â”‚  â”‚  â”‚
â”‚                                  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                â”‚                          â”‚  â”‚
â”‚  â”‚  Red Agent   â”‚ â”€â”€ mutate â”€â”€â”€â–º â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  â”‚
â”‚  â”‚  (Adaptive   â”‚                â”‚  â”‚  Deterministic     â”‚  â”‚  â”‚
â”‚  â”‚  Adversary)  â”‚                â”‚  â”‚  Grader (no LLM)   â”‚  â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚  â”‚
â”‚                                  â”‚                          â”‚  â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  GET /score    â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚  â”‚
â”‚  â”‚  W&B Tracker â”‚ â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  â”‚  Schema Drift      â”‚  â”‚  â”‚
â”‚  â”‚  (live runs) â”‚                â”‚  â”‚  Engine            â”‚  â”‚  â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚  â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Key files:**
- `env/soc_environment.py` â€” Core RL environment (reset / step / reward)
- `env/red_agent.py` â€” Adaptive adversary: IP rotation, credential rotation, MITRE escalation
- `env/schema_drift.py` â€” SIEM-agnostic field name mutation engine
- `tasks/hard_task.py` â€” 4-stage APT kill chain task definition
- `graders/hard_grader.py` â€” Deterministic verifiable scorer (no hallucination possible)
- `server/app.py` â€” FastAPI server + live SOC dashboard (2,000+ lines)
- `training/colab_grpo_all_in_one.py` â€” GRPO + Unsloth training (Colab-ready, W&B mandatory)

---

## Try It Right Now

**The entire environment is live on Hugging Face:**

> ðŸ”— **[aditya9605-meta-hackathon-finale.hf.space/web](https://aditya9605-meta-hackathon-finale.hf.space/web)**

1. Select **HARD / APT Kill Chain** from the dropdown
2. Check **Deterministic Demo Mode** (reproducible for judges)
3. Click **Initialize Environment**
4. Click **Run Autonomous Demo**

**Watch the agent execute all five kill chain steps in under 10 seconds, then self-evaluate to 80%.**

Or go manual â€” initialize, then execute the steps yourself in order: `isolate_host WEB-SRV-01` â†’ `isolate_host FINANCE-DB-01` â†’ `block_ip 198.51.100.77` â†’ `flag_user backup-svc` â†’ `escalate_alert`. See if you can beat the agent's ordering bonus.

---

## Why This Matters Beyond This Hackathon

The AI cybersecurity market is **$30.9 billion** and growing at **24% annually**. The projected demand for SOC analysts by 2033 is up **332%**. **There literally aren't enough humans to fill those roles.**

The answer isn't more analysts. **The answer is smarter AI â€” trained in environments that actually prepare it for adversarial conditions, not sanitized historical datasets.**

Static fine-tuning teaches models what attacks looked like yesterday.

**Adversarial RL teaches models how to respond to attacks they've never seen.**

That's the difference between memorization and reasoning. **That's SOC Simulator.**

---

## Links

| Resource | URL |
|----------|-----|
| ðŸš€ Live Demo | [aditya9605-meta-hackathon-finale.hf.space/web](https://aditya9605-meta-hackathon-finale.hf.space/web) |
| ðŸ¤— Hugging Face Space | [META_HACKATHON_FINALE](https://huggingface.co/spaces/Aditya9605/META_HACKATHON_FINALE) |
| ðŸ“Š W&B Training Runs | [soc-simulator-grpo](https://wandb.ai/rajeaditya999-/soc-simulator-grpo) |
| ðŸ’» Source Code | [github.com/Raje0906/META_HACKATHON](https://github.com/Raje0906/META_HACKATHON) |
| ðŸ“– API Docs | [/docs](https://aditya9605-meta-hackathon-finale.hf.space/docs) |

---

*Built with â¤ï¸, too much caffeine, and a genuine belief that the next generation of cybersecurity will be trained â€” not programmed.*

*â€” Aditya Raje, Meta Hackathon 2026*



