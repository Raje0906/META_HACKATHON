---
title: SOC Simulator
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# SOC Simulator - OpenEnv Cybersecurity RL Environment

`SOC Simulator` is an OpenEnv-compliant environment for training LLM agents to act as SOC analysts in partially observable, adversarial security workflows.

It targets Hackathon themes:
- Theme #4 (Self-Improvement): adaptive Red Agent that mutates attacks.
- Theme #3.1 (Professional Tasks): realistic tool/API style SOC operations.
- Theme #3.2 bonus angle: schema drift and robust action parsing.

## Links for Judges

- Hugging Face Space: [aditya9605-meta-hackathon-finale](https://aditya9605-meta-hackathon-finale.hf.space)
- API docs: [Space /docs](https://aditya9605-meta-hackathon-finale.hf.space/docs)
- Interactive dashboard: [Space /web](https://aditya9605-meta-hackathon-finale.hf.space/web)
- W&B run: [soc-simulator-grpo](https://wandb.ai/rajeaditya999-/soc-simulator-grpo)
- Pitch script: `hackathon_pitch.md`
- Blog draft: `outputs/hf_blog_post.md`

## Minimum Requirement Checklist (Hackathon)

- OpenEnv latest-compatible environment: `openenv.yaml` + FastAPI server in `server/app.py`.
- Training script using TRL/Unsloth:
  - `training/colab_unsloth_grpo.py`
  - `training/colab_unsloth_ppo.py`
- Evidence of training progress:
  - `outputs/evals/scores.json`
  - `outputs/evals/reward_curve_baseline_vs_trained.png`
  - `outputs/evals/red_vs_blue_curve.png`
- Environment hosted on Hugging Face Space: [live Space URL](https://aditya9605-meta-hackathon-finale.hf.space)
- Short writeup and pitch script linked in repo:
  - `outputs/hf_blog_post.md`
  - `hackathon_pitch.md`

## What Makes This Environment Challenging

- Adaptive adversary (`env/red_agent.py`) rotates attacker IPs, credentials, and tactics.
- Dynamic threat intel (`env/dynamic_input.py`) can source live malicious IP indicators.
- Schema drift (`env/schema_drift.py`) mutates event keys during episodes.
- Multi-stage tasks require state tracking, not one-step keyword matching.
- Dense reward with penalties and early completion bonus to reduce reward hacking.

## Tasks

- `easy_phishing_login`: phishing + compromised account.
- `medium_brute_force_geo`: brute-force correlation + geo anomaly + host isolation.
- `hard_apt_multistage`: recon -> initial access -> lateral movement -> exfiltration.

## Reward and Evaluation Evidence

Run:
```bash
python training/red_vs_blue_loop.py
```

Generated artifacts:
- `outputs/evals/scores.json`
- `outputs/evals/reward_curve_baseline_vs_trained.png`
- `outputs/evals/red_vs_blue_curve.png`

Latest run snapshot (from current `scores.json`):
- Mean uplift vs baseline: `+0.377`
- Easy uplift: `+0.542` (`q_best_action=block_ip`)
- Medium uplift: `+0.227` (`q_best_action=block_ip`)
- Hard uplift: `+0.363` (`q_best_action=block_ip`)

Note: this snapshot is from a short reliability run. Re-run the same script for a longer 50-episode benchmark before final judging.

## Reward Design and Anti-Hacking Safeguards

- Multiple signals: step reward + terminal grading + final score deltas.
- Penalties for false positives, redundant actions, unnecessary ignore, and missed threats.
- Early completion bonus to favor decisive mitigation over passive looping.
- Schema drift support (`source_ip`/`src_addr`/`remote_ip` and user key variants) to reduce brittle shortcuts.
- Deterministic graders (`graders/`) used as verifiable reward sources.

## Minimal Training Scripts (Hackathon Requirement)

- GRPO + Unsloth (Colab-oriented): `training/colab_unsloth_grpo.py`
- PPO + TRL minimal example: `training/colab_unsloth_ppo.py`

## Quick Start

Install and run:
```bash
uv pip install -r requirements.txt
python -m server.app
```

Run tests:
```bash
pytest tests -v
```

Run inference benchmark:
```bash
python inference.py
```

## Reproducibility (Suggested Judge Flow)

```bash
uv pip install -r requirements.txt
python -m server.app
python training/red_vs_blue_loop.py
```

## OpenEnv Endpoints

- `POST /reset`
- `POST /step`
- `GET /state`
- `GET /score`
- `GET /explain`
- `GET /difficulty`
- `GET /health`
