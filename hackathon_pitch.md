# SOC Simulator: Deep Technical Architecture & Mechanics

This document provides a highly detailed, technical breakdown of the SOC Simulator. It explains exactly how the internal state machine, reward gradient, adversarial generation, and difficulty scaling operate under the hood. Provide this to Claude to generate comprehensive ReadMes, technical blogs, or deep-dive pitch explanations.

---

## 1. The OpenEnv Compliance Layer
At its core, the SOC Simulator implements the **OpenAI Gym / OpenEnv** standard interface. It treats an enterprise Security Operations Center as an RL state machine, where the AI Analyst is the "Agent".

*   **`obs = env.reset(task_id)`**: Initializes the state machine. It seeds the pseudo-random number generator (if provided), instantiates the chosen scenario (e.g., `hard_apt_multistage`), and returns the `SOCObservation`, which mirrors an analyst's dashboard: active network alerts, an array of raw JSON SIEM logs, and system posture flags.
*   **`obs, reward, done, info = env.step(action)`**: The agent selects an `ActionType` (`BLOCK_IP`, `FLAG_USER`, `ISOLATE_HOST`, etc.). The environment evaluates the action against a hidden ground-truth mapping, calculates a dense scalar reward, and advances the game clock. If maximum steps are reached or the threat is neutralized, `done` is set to `True`.

This standardization is critical because it means any off-the-shelf RL framework (Ray RLlib, Hugging Face TRL, Unsloth PPO) can fine-tune an LLM on this environment without custom training loops.

---

## 2. Dense Reward Function & Ground Truth Evaluator
Training an LLM for agentic workflows requires a dense, highly specialized reward gradient. The grader does not just award a `1` or `0` at the end of the episode; it provides step-by-step reinforcement.

**Reward Configurations:**
*   **Decisive Action Reward (`+0.25` - `+0.30`)**: Correctly identifying and isolating compromised hosts, or blocking malicious IPs, generates positive reinforcement.
*   **Stage Detection Bonus (`+0.10`)**: In multi-stage APT tasks, uncovering sequential stages of the kill chain (Reconnaissance -> Initial Access -> Lateral Movement) grants chained bonuses.
*   **False Positive Penalties (`-0.15`)**: RL agents naturally attempt to "guess" or execute broad blocks to maximize reward. In cybersecurity, blocking a benign production IP (False Positive) is devastating. The environment strictly penalizes isolating benign users/hosts to naturally select against "trigger-happy" agents.
*   **Timestep Cost (`-0.02`)**: To discourage the LLM from taking excessive steps or repeatedly querying non-actionable logs, the system detracts a minor cost per step.
*   **Missed Threat Penalty (`-0.30` per threat)**: Evaluated when `done=True`. If the agent misses active threats, the final score incurs a massive end-game penalty.

---

## 3. The Red Agent: Adaptive Adversarial Mutation (Theme 4)
The Red Agent serves as an autonomous adversarial adversary. Its objective is to prevent the Blue Agent (the LLM) from memorizing static training data. It enforces a "Continual Learning" curriculum.

**The Memory Extraction Process:**
When `reset()` is called, the Red Agent intercepts the API payload. If `enable_red_agent` is active, it extracts a `BlueMemory` dataclass mapping the Blue Agent's actions from the *previous* episode.

**The Mutation Strategies:**
If the Blue Agent successfully mitigated a threat (e.g., flagged `alice.chen` and blocked `185.x.x.x`), the Red Agent dynamically alters the next episode's ground constraints:
1.  **Credential Rotation**: The Red Agent queries a `CREDENTIAL_POOL` (e.g., `backup-svc`, `devops`, `infra-svc`) to select a pristine username. It injects this user directly into the active SIEM logs and alerts, replacing the baseline `alice.chen`.
2.  **IP Rotation**: The Red Agent queries IANA Documentation ranges (`198.51.100.x`, `203.0.113.x`) to rotate out the attacking infrastructure, rendering previously learned static filters useless.
3.  **Tactic Escalation**: If the Blue Agent achieves an episode score `> 0.75`, the Red Agent escalates its MITRE ATT&CK techniques, injecting obfuscation (T1027) or log modification indicators to drastically increase difficulty.

---

## 4. Schema Drift Engine (Patronus AI Bonus)
Production SIEM platforms (Splunk, Datadog) frequently alter their JSON exports following software updates. An LLM agent reliant on static regex or predefined `Pydantic` schema definitions will crash instantly in production.

**The Implementation:**
The `SchemaDriftEngine` monitors the step count. Randomly, it applies structural transmutations to the raw event dictionaries flowing to the agent.
*   **Version 1 (Static)**: `{"source_ip": "1.1.1.1", "user_id": "alice.chen"}`
*   **Version 2 (Drift)**: `{"remote_ip": "1.1.1.1", "account_name": "alice.chen"}`
*   **Version 3 (Drift)**: `{"src": "1.1.1.1", "actor": "alice.chen"}`

This specifically targets the Patronus AI evaluation bonus criteria: evaluating how well the LLM reasons through unexpected, undocumented disruptions in data architecture.

---

## 5. Live Threat Intelligence Pipeline
To ensure the simulation remains hyper-relevant, the `DynamicInputPipeline` connects directly to external intelligence nodes.

*   **URLhaus Integration**: Using HTTP requests, the environment queries the Abuse.ch URLhaus API for active, freshly reported malware distribution URLs and resolves their A-Records.
*   **Feodo Tracker Integration**: It supplements the query by scraping the Feodo Tracker IP blocklist for active Botnet C2 infrastructure.
*   **Dynamic Injection**: Instead of generating a random string, the `EasyTask` natively injects these live, verified malicious IPs into the `raw_log` JSON fields. This creates a simulator grounded entirely in current-day telemetry.

---

## 6. Real-Time Dynamic Difficulty Rescaling
The simulation scales difficulty proportionally to the LLM's competence.
The system tracks the rolling average of the last 5 episode grading scores:
*   If the LLM score dips `< 0.40`, the environment reduces the event volume and uses glaringly obvious IPs, allowing the model to recover policy stability.
*   If the LLM score breaches `> 0.75`, the simulator triples the event volume, injects benign decoy alerts to bait False Positives, and spawns concurrent attack streams, pushing the LLM to its absolute reasoning threshold.
