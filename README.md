---
title: SOC Simulator
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# 🛡️ SOC Simulator — AI Cybersecurity Environment

SOC Simulator is an **OpenEnv-compliant** reinforcement learning environment that simulates a modern Security Operations Center (SOC). It provides a high-fidelity playground to evaluate autonomous AI agents operating as Tier-1 / Tier-2 SOC analysts. 

The environment streams SIEM logs and active security alerts to the agent, evaluates its protective response actions (e.g., blocking IPs, isolating machines, flagging users), and applies dense reward scoring to optimize performance.

---

## 🌟 Upgraded Capabilities (Hackathon Theme Alignment)

This project strictly targets **Theme #4 (Self-Improvement)** and the **Theme #3.2 Patronus AI Bonus (Consumer Workflows with Schema Drift)**. The environment features fully dynamic and adversarial mechanisms:

1. **🔴 RedAgent: Evolving Threat Actor (Theme #4)**
   Simulates an adaptive adversary that learns from the blue agent's previous actions. If an attack is caught, the Red Agent rotates IPs, alters credentials, jitters timestamps, and escalates to obfuscation techniques (MITRE T1027). This forces the LLM to learn driving its own capability growth instead of optimizing fixed tasks.

2. **🌐 Dynamic Threat Intel Pipeline**
   Integrates directly with live threat feeds (*URLhaus* and *Feodo Tracker*) to seed scenarios with real, active botnet and malware IPs, ensuring the agent learns practical threat hunting over static memorization.

3. **⚖️ Auto-Scaling Challenge**
   Features a performance-based difficulty slider. Based on a rolling average of the agent's recent scores, the environment autonomously simplifies or escalates the attack complexity to maintain optimal engagement.

4. **🧩 Schema Drift Engine (Theme #3.2 Patronus AI Bonus)**
   Provides a Multi-step workflow environment where underlying data schemas mutate. Without warning, critical keys like `source_ip`, `user_id`, and `event_type` will randomly mutate into variations like `remote_ip`, `account_name`, and `log_type` mid-episode, brutally testing model robust parsing.

---

## 📂 Project Structure

```text
├── env/
│   ├── soc_environment.py  # Core OpenEnv RL logic (step, reset, reward generation)
│   ├── red_agent.py        # Mutates attack tactics across episodes
│   ├── dynamic_input.py    # Fetches live OSINT (URLhaus) & scales difficulty
│   └── schema_drift.py     # Forces structural field drift in observations
│
├── tasks/                  # Task scenarios determining the attack chain
│   ├── easy_task.py        # Phishing + Malicious Login
│   ├── medium_task.py      # Brute-force credentials + Impossible geo-travel
│   └── hard_task.py        # Multi-stage APT kill chain (Recon → Exfiltration)
│
├── graders/                # Evaluates correctness of the LLM actions
│   ├── easy_grader.py
│   ├── medium_grader.py
│   └── hard_grader.py
│
├── training/
│   └── red_vs_blue_loop.py # Standalone evaluation script charting Red vs Blue scores
│
├── server/
│   └── app.py              # FastAPI server implementing the OpenEnv HTTP API
│
├── models.py               # Pydantic schema validation for actions & states
├── inference.py            # Baseline LLM inference script for open-source AI
├── openenv.yaml            # Manifest for OpenEnv orchestrator
└── tests/                  # Pytest test suite ensuring logic stability
```

---

## 🚀 Getting Started

### 1. Start the Environment API
Install the dependencies using `uv` (recommended) or `pip`:
```bash
uv pip install -r requirements.txt
python -m server.app
```
*The OpenEnv API will spin up on `http://localhost:8000` alongside an interactive web-based playground (`/web`).*

### 2. Run the Red vs Blue Training Loop
Run the automated standalone test that pits a heuristic-based Blue Agent against the mutating Red Agent over 50 scenarios. It tracks scores, performance, and produces evaluation charts.
```bash
python training/red_vs_blue_loop.py
```
*Outputs are saved to `outputs/evals/red_vs_blue_curve.png`.*

### 3. OpenEnv LLM Inference
Supply an API key to test an actual foundational model against the environment logic:
```bash
python inference.py
```

### 4. TRL & Unsloth Colab Training
As per Hackathon minimum requirements, a Colab-ready `trl` PPO training loop is included. It imports Unsloth, generates actions, and steps through the OpenEnv APIs:
```bash
# View the script logic tailored for Jupyter Notebook runtimes:
cat training/colab_unsloth_ppo.py
```

---

## 📡 API Contract (OpenEnv Standard)
* `POST /reset`: Initializes an episode and returns the `SOCObservation`. Accepts `custom_params` to forcefully toggle RedAgent, Schema Drift, or live threat intel.
* `POST /step`: Submit an analyst action (e.g., `block_ip`, `isolate_host`). Returns state details & step rewards.
* `GET /score`: Retrieve final episode grade (`0.0` – `1.0`).
* `GET /difficulty`: View current dynamic difficulty recommendations.
