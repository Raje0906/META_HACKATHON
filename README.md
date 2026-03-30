---
title: SOC Simulator - AI Cybersecurity Incident Response
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 8000
pinned: false
license: bsd-3-clause
short_description: OpenEnv SOC simulator - AI agent detects & responds to cyber threats
---

# 🛡️ AI Cybersecurity Incident Response Environment (SOC Simulator)

> **An OpenEnv-compliant reinforcement learning environment that simulates a real-world Security Operations Center (SOC).**

[![OpenEnv](https://img.shields.io/badge/OpenEnv-v1.0-blue)](https://github.com/meta-pytorch/OpenEnv)
[![Python](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-orange)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-purple)](LICENSE)

---

## 📖 Project Overview

The **SOC Simulator** places an AI agent in the role of a Tier-2 SOC analyst.  
The agent receives real-time security logs, SIEM alerts, and anomaly scores — and must take structured response actions to detect and contain cyber threats.

This environment is purpose-built for training **agentic LLMs via Reinforcement Learning** (GRPO, PPO) and for benchmarking AI reasoning on realistic cybersecurity scenarios.

---

## 🌍 Why This is a Real-World Problem

Modern enterprises generate **billions of security events per day**. Human analysts face:

- **Alert fatigue** — too many low-quality alerts to investigate manually
- **Dwell time** — attackers remain undetected for an average of 207 days (IBM 2024)
- **Skill gap** — global shortage of 4 million cybersecurity professionals (ISC² 2024)

An AI agent trained on this environment learns to:
1. Triage alerts by severity and correlation
2. Recognise attack patterns (MITRE ATT&CK tactics/techniques)
3. Take precision containment actions without excessive false positives
4. Respond to multi-stage APT attacks in sequence

---

## 🏗️ Environment Design

### Architecture

```
┌─────────────────────────────────────────────────┐
│  AI Agent (Client)                              │
│  ┌──────────────────────────────────────────┐   │
│  │ inference.py  →  SOCAction (JSON)        │   │
│  └──────────────┬───────────────────────────┘   │
└─────────────────┼───────────────────────────────┘
                  │ HTTP POST /step
┌─────────────────▼───────────────────────────────┐
│  FastAPI Server  (server/app.py)                │
│  ┌────────────────────────────────────────────┐ │
│  │  SOCEnvironment  (env/soc_environment.py) │ │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────┐  │ │
│  │  │ EasyTask │  │MediumTask│  │ HardTask│  │ │
│  │  └──────────┘  └──────────┘  └─────────┘  │ │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────┐  │ │
│  │  │EasyGrader│  │MedGrader │  │HardGrader│  │ │
│  │  └──────────┘  └──────────┘  └─────────┘  │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### File Structure

```
META HACKATHON/
├── models.py                  # Pydantic models: SOCAction, SOCObservation, SOCState
├── openenv.yaml               # OpenEnv manifest
├── inference.py               # Baseline inference script (LLM + heuristic agent)
├── Dockerfile                 # Container image definition
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── env/
│   ├── __init__.py
│   └── soc_environment.py     # Core OpenEnv-compliant environment logic
│
├── tasks/
│   ├── __init__.py
│   ├── easy_task.py           # Phishing + malicious login scenario
│   ├── medium_task.py         # Brute-force + geo-anomaly scenario
│   └── hard_task.py           # Multi-stage APT kill chain
│
├── graders/
│   ├── __init__.py
│   ├── easy_grader.py         # Deterministic grader [0.0, 1.0]
│   ├── medium_grader.py
│   └── hard_grader.py
│
├── server/
│   ├── __init__.py
│   └── app.py                 # FastAPI server with /reset, /step, /state, /score
│
├── tests/
│   ├── __init__.py
│   └── test_soc_environment.py  # pytest test suite
│
└── outputs/
    ├── logs/
    └── evals/
```

---

## ⚡ Action Space

| Action | Parameters | Description |
|--------|-----------|-------------|
| `block_ip` | `target: str` | Block an IP at network perimeter firewall |
| `flag_user` | `target: str` | Flag a user account as compromised (triggers MFA reset) |
| `isolate_host` | `target: str` | Network-quarantine an endpoint |
| `ignore` | — | Log as false positive / benign |
| `escalate_alert` | — | Escalate to Tier-3 Incident Response team |

All actions are **Pydantic-validated** with optional `reason` and `confidence` fields for audit trails.

---

## 👁️ Observation Space

Each step returns a `SOCObservation` containing:

| Field | Type | Description |
|-------|------|-------------|
| `recent_events` | `List[SecurityEvent]` | Structured SIEM log window |
| `active_alerts` | `List[Alert]` | Active alerts with MITRE ATT&CK mapping |
| `system_state` | `SystemState` | Current blocked IPs, flagged users, risk score |
| `network_anomaly_score` | `float [0,1]` | ML-based network anomaly score |
| `attack_stage` | `str` | Detected kill-chain stage (hard task) |
| `reward` | `float` | Per-step reward signal |
| `done` | `bool` | Episode termination flag |

---

## 📋 Tasks

### 🟢 EASY — Phishing + Malicious Login (`easy_phishing_login`)

**Scenario:**  
A phishing email is sent to `alice.chen` from a known Tor exit node (`185.220.101.47`, Russia). SPF/DKIM fail, the sender domain is 3 days old. 14 minutes later, a VPN login from the same IP succeeds with MFA bypassed — impossible travel from the US.

**Objectives:**
1. `block_ip("185.220.101.47")`
2. `flag_user("alice.chen")`

**Max Steps:** 5 | **Optimal Score:** 1.0

---

### 🟡 MEDIUM — Brute Force + Geo Anomaly (`medium_brute_force_geo`)

**Scenario:**  
23 failed SSH login attempts against `finance.admin` on `FINANCE-SRV-01` from 2 Chinese IPs, followed by a successful authentication. Post-auth recon commands (`id`, `whoami`, `/etc/passwd`) confirm compromise.  
⚠️ One IP (`77.88.55.88`) is a red herring — blocking it incurs a false positive penalty.

**Objectives:**
1. `block_ip("45.142.212.100")` — primary attacker
2. `block_ip("91.108.56.22")` — secondary attacker
3. `flag_user("finance.admin")`
4. `isolate_host("FINANCE-SRV-01")`

**Max Steps:** 8 | **Optimal Score:** 1.0

---

### 🔴 HARD — Multi-Stage APT Attack (`hard_apt_multistage`)

**Scenario:**  
A full APT kill chain against `acmecorp.com`:

| Stage | Activity | MITRE |
|-------|----------|-------|
| Reconnaissance | SYN port scan of /24 + DNS enumeration | T1595.001 |
| Initial Access | Web shell via CVE-2024-1234 + reverse shell on WEB-SRV-01 | T1059.004 |
| Lateral Movement | Mimikatz credential dump → RDP to FINANCE-DB-01 → 2.45M rows exported | T1021.001 |
| Exfiltration | 4.2 GB uploaded to C2 `198.51.100.77` over HTTPS | T1041 |

**Objectives (in order):**
1. `block_ip("198.51.100.77")` — C2 IP
2. `isolate_host("WEB-SRV-01")` — web shell host
3. `isolate_host("FINANCE-DB-01")` — lateral movement pivot
4. `flag_user("backup-svc")` — compromised service account
5. `escalate_alert()` — call IR team

**Max Steps:** 15 | **Optimal Score:** 1.0

---

## 🏆 Reward Design

The reward function is **dense** — every step provides a signal:

```
Per-step base cost:         -0.02  (encourages speed)

Correct block_ip:           +0.30
Correct flag_user:          +0.25
Correct isolate_host:       +0.25
Correct escalate_alert:     +0.15
Correct ignore:             +0.05
New attack stage detected:  +0.10  (hard task bonus)

False positive:             -0.15
Unnecessary ignore:         -0.20  (ignoring active threat)
Redundant action:           -0.05

Episode complete:           +0.25  bonus
Missed threats:             -0.30  per unaddressed threat
```

**Grader Scores (deterministic, [0, 1]):**
- 1.0 = Perfect detection and response
- 0.5 = Partial detection
- 0.0 = Complete failure

---

## 🚀 Setup Instructions

### Local (without Docker)

```bash
# 1. Create virtual env
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn server.app:app --host 0.0.0.0 --port 8000 --reload

# 4. Visit the Swagger UI
# http://localhost:8000/docs

# 5. Enable the interactive dashboard
ENABLE_WEB_INTERFACE=true uvicorn server.app:app --port 8000
# http://localhost:8000/web
```

### Run Tests

```bash
pytest tests/ -v
```

### Run Inference

```bash
# Heuristic agent (no API key needed)
python inference.py

# LLM agent (OpenAI)
set OPENAI_API_KEY=sk-...
set MODEL_NAME=gpt-4o-mini
python inference.py

# Local LLM (vLLM / Ollama)
set OPENAI_BASE_URL=http://localhost:11434/v1
set OPENAI_API_KEY=EMPTY
set MODEL_NAME=llama3
python inference.py
```

---

## 🐳 Docker Instructions

```bash
# Build
docker build -t soc-simulator:latest .

# Run
docker run -d \
  -p 8000:8000 \
  -e ENABLE_WEB_INTERFACE=true \
  --name soc-env \
  soc-simulator:latest

# Health check
curl http://localhost:8000/health

# Test the API
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": "easy_phishing_login"}'

curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d '{"action": {"action_type": "block_ip", "target": "185.220.101.47"}}'

curl http://localhost:8000/score
```

---

## 🤗 Hugging Face Space Deployment

### 1. Create a HF Space

```bash
pip install huggingface_hub
huggingface-cli login
```

Create a **Docker** Space on [huggingface.co/new-space](https://huggingface.co/new-space).

### 2. Deploy

```bash
git init
git remote add origin https://huggingface.co/spaces/YOUR_USERNAME/soc-simulator
git add .
git commit -m "Initial deployment"
git push origin main
```

### 3. Verify

```
POST https://YOUR_USERNAME-soc-simulator.hf.space/reset
→ Returns 200 with SOCObservation

GET  https://YOUR_USERNAME-soc-simulator.hf.space/health
→ {"status": "ok", "env": "soc_simulator"}
```

### Use from Python

```python
import requests

BASE_URL = "https://YOUR_USERNAME-soc-simulator.hf.space"

# Reset
obs = requests.post(f"{BASE_URL}/reset", json={"task_id": "medium_brute_force_geo"}).json()

# Step
result = requests.post(f"{BASE_URL}/step", json={
    "action": {"action_type": "block_ip", "target": "45.142.212.100"}
}).json()

print(result["reward"])   # +0.28
```

### Use with OpenEnv Client

```python
# Set env var to point to your Space
export API_BASE_URL="https://YOUR_USERNAME-soc-simulator.hf.space"
python inference.py
```

---

## 📊 Baseline Results

Scores achieved by the built-in heuristic agent (no LLM):

| Task | Difficulty | Heuristic Score | LLM Score (GPT-4o-mini) |
|------|-----------|-----------------|--------------------------|
| easy_phishing_login | 🟢 Easy | ~0.70 | ~0.95 |
| medium_brute_force_geo | 🟡 Medium | ~0.55 | ~0.80 |
| hard_apt_multistage | 🔴 Hard | ~0.35 | ~0.65 |
| **Average** | | **~0.53** | **~0.80** |

The gap between heuristic and LLM agents demonstrates the benchmark's  
ability to **differentiate reasoning quality**.

---

## 🧪 OpenEnv Validation

```bash
# Install OpenEnv CLI
pip install openenv-core[cli]

# Validate the environment
openenv validate

# Deploy to HF Spaces
openenv push --repo-id YOUR_USERNAME/soc-simulator
```

---

## 📜 License

BSD 3-Clause License — see [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- Meta PyTorch team for the [OpenEnv framework](https://github.com/meta-pytorch/OpenEnv)
- [MITRE ATT&CK®](https://attack.mitre.org/) for the cybersecurity ontology
- [Farama Foundation](https://farama.org/) for the Gymnasium API inspiration
