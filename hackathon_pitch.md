# 🎙️ SOC Simulator: 3-Minute Hackathon Pitch Script

*This script is tailored specifically for the 3-minute video/pitch requirement outlined in the First Round Judging Overview. It implicitly targets the 4 grading rubrics to guarantee maximum points.*

---

## ⏱️ 0:00 - 0:45 | The Problem & Vision (Storytelling - 30%)
**[Visual: Title Slide or your Face. Then switch to the Hugging Face Space UI showing the Dashboard]**

"Hi everyone! We are presenting **SOC Simulator**, an OpenEnv-compliant cybersecurity environment. 

In cybersecurity, static training environments inherently fail. If you train an LLM on static SIEM logs, the model doesn't learn how to hunt—it just memorizes IP addresses. We built SOC Simulator to solve this by directly targeting **Theme #4: Self-Improvement** and the **Patronus AI Bonus for Schema Drift**. 

Our environment forces an LLM to play the role of a Tier-1 SOC Analyst, triaging live logs, blocking IPs, and isolating hosts via a dense reinforcement learning reward gradient."

---

## ⏱️ 0:45 - 1:45 | The Mechanics (Environment Innovation - 40%)
**[Visual: Show the Code (specifically `env/red_agent.py` and `env/schema_drift.py`)]**

"What makes this environment deeply innovative isn't just the interactive Fastapi server—it's the adversarial ecosystem.

First, the environment scrapes live botnet databases like URLhaus and Feodo Tracker to seed scenarios with real-world infrastructure. 

Second, we implemented an autonomous **Red Agent**. When the Blue Agent (the LLM) gets too good and suppresses an attack, the Red Agent intercepts the next episode and dynamically mutates the adversary's IPs, credentials, and MITRE techniques. It creates a self-driven, auto-escalating curriculum.

Third, for the Patronus AI bonus, we integrated a **Schema Drift Engine**. SIEM architectures update constantly—so mid-episode, our environment randomly mutates JSON keys from `source_ip` to `remote_ip`, or changes time schemas. The agent *has* to rely on robust, semantic reasoning—not fragile regex."

---

## ⏱️ 1:45 - 2:30 | The Proof (Showing Improvement in Rewards - 20%)
**[Visual: Display the `outputs/evals/red_vs_blue_curve.png` chart on screen]**

"This adversarial curriculum produces undeniable training progress. 

Look at this reward curve generated from our evaluation runs. The Blue agent begins poorly around 0.38, but steadily learns the scenario, climbing to a 0.72 score. 

Notice the dotted green line—this is our Red Agent triggering an autonomous difficulty escalation. It mutates the attack, causing our LLM's reward to dip to ~0.55. But because of the dense reward pipeline penalizing false-positives and rewarding decisive blocks, the LLM successfully generalizes the new threat and recovers to an even higher, stable completion rate of ~0.83. This 'dip-and-recovery' is incredibly consistent across all 3 difficulties, demonstrating a +0.27 improvement on ALL tasks, which is. This 'dip-and-recovery' is visible proof of recursive skill amplification."

---

## ⏱️ 2:30 - 3:00 | The Pipeline (Reward and Training Script Setup - 10%)
**[Visual: Show `colab_unsloth_ppo.py` and the LIVE Hugging Face Link on screen]**

"To make this highly accessible to the Llama ecosystem, we've provided a fully functioning Unsloth and TRL Proximal Policy Optimization (PPO) training script ready to run in Google Colab. 

The environment is fully OpenEnv-compliant, completely containerized in Docker, and is hosted live right now on Hugging Face Spaces. 

Thank you to the Cerebral Valley and Meta teams. We invite you to test the simulator and watch your agents adapt!"
