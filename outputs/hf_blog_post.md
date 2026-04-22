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
As demonstrated in the evaluation curve above, the Red Agent's periodic escalations systematically push the Blue Agent's rewards down. However, because of our dense reward penalty for false-positives and time-wasting actions, the Blue Agent rapidly generalizes the novel attack vector.

The results are remarkably consistent. In all three task difficulties, from Basic Phishing to Multi-Stage APTs, the agent recovers to a stable success rate of over 0.83. This +0.27 improvement across all scenarios signifies genuine, reusable cybersecurity logic amplification. 

Check out the environment on our Hugging Face Space to try it yourself!
