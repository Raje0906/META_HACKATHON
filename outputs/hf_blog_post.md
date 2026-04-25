---
title: "SOC Simulator: Training an RL Agent to Hunt Cyber Threats"
tags: ["reinforcement-learning", "cybersecurity", "openenv", "llama-3", "hackathon"]
---

# SOC Simulator: Training an RL Agent to Hunt Cyber Threats

We built **SOC Simulator**, an OpenEnv-compliant cybersecurity environment, to teach LLMs how to perform real Security Operations Center (SOC) incident response.

Training large language models on static SIEM (Security Information and Event Management) logs has a fundamental flaw: the model doesn't learn how to "hunt" for threats; it merely memorizes static IPs and payloads. We solved this by developing an environment with high schema drift, live botnet scraping, and dense reinforcement learning (RL) reward pipelines.

### The Adversarial Ecosystem
Our environment features an autonomous **Red Agent** that reacts to the completions of the Blue Agent (our Llama-3 based analyst). Whenever the Blue Agent successfully suppresses an attack—such as isolating an infected host or blocking a Command & Control IP—the Red Agent escalates the difficulty in the next episode. It silently mutates the attacker's infrastructure, switching out threat IPs and shifting MITRE ATT&CK techniques.

This creates a self-driven, auto-escalating curriculum where the LLM is constantly forced to adapt to novel threats.

![Red vs Blue Reward Curve](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/red_vs_blue_curve.png)

### Proof of Learning
We evaluate using a baseline-vs-trained protocol (`training/red_vs_blue_loop.py`) and publish both the raw JSON metrics and plots under `outputs/evals/`.

Our claim is intentionally strict: we only report values directly present in `outputs/evals/scores.json` from the latest run. This avoids overfitting the narrative to one lucky episode and makes the evidence reproducible for judges.

From the latest run:
- mean uplift vs baseline: **+0.377**
- easy task uplift: **+0.542**
- medium task uplift: **+0.227**
- hard task uplift: **+0.363**

We also hardened the policy against reward hacking by combining step-level rewards, terminal grading, and action-level penalties (false positives, redundant actions, unnecessary ignore, and missed-threat penalties), plus schema-drift robustness checks.

Check out the environment on our Hugging Face Space to try it yourself!
