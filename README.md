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

### Hackathon theme alignment (OpenEnv India 2026)

| Theme | How this project maps |
|------|------------------------|
| **#1 Multi-Agent** | **Blue** (defender LLM / analyst policy) vs **Red** (adaptive adversary in `env/red_agent.py`): competitive dynamics, partial observability, and curriculum-style escalation. |
| **#2 Long-horizon planning** | Multi-step episodes (easy → medium → hard), sparse terminal grading plus dense step rewards; hard task follows a multi-stage kill chain requiring sustained reasoning. |
| **#3.1 Professional tasks** | Tool-like actions (`block_ip`, `flag_user`, `isolate_host`, …) over structured SIEM-style observations and HTTP API (`reset` / `step`), not pattern-matching shortcuts. |
| **#4 Self-improvement** | Red agent mutates scenarios; training (GRPO) shows measurable uplift vs baseline on live Space rollouts (`outputs/evals/`). |
| **#5 Wild card** | Cyber SOC + schema drift + optional live threat intel — niche domain for LLM RL. |

## Non-negotiable checklist (organizers)

Use this list when you (the **team leader**) submit **one** official entry. Missing items put the team at a serious disadvantage.

| Requirement | Where it lives |
|-------------|----------------|
| **OpenEnv (latest)** — build on the framework, don’t reinvent it | `openenv.yaml`, FastAPI app `server/app.py`, Gym-style `reset` / `step` / `state`, Pydantic models in `models.py` |
| **Working training script** (Unsloth **or** HF TRL **or** other RL stack), **ideally re-runnable in Colab** | **Primary:** [`training/colab_grpo_all_in_one.py`](training/colab_grpo_all_in_one.py) (copy into a Colab notebook cell or open via Colab → *File → Upload*). **Also:** [`training/colab_unsloth_grpo.py`](training/colab_unsloth_grpo.py), [`training/colab_unsloth_ppo.py`](training/colab_unsloth_ppo.py) |
| **Evidence you trained** — at minimum **loss and reward** from a real run | **Reward / eval curves (repo):** [`outputs/evals/red_vs_blue_curve.png`](outputs/evals/red_vs_blue_curve.png), [`outputs/evals/reward_curve_baseline_vs_trained.png`](outputs/evals/reward_curve_baseline_vs_trained.png), [`outputs/evals/scores.json`](outputs/evals/scores.json). **Training loss / KL / rewards (W&B):** [soc-simulator-grpo](https://wandb.ai/rajeaditya999-/soc-simulator-grpo) |
| **Short writeup or video** (HF mini-blog **or** an **under-two-minute** YouTube video) — **public URL only** (no large video files in the Space repo) | **Draft in repo:** [`outputs/hf_blog_post.md`](outputs/hf_blog_post.md) → publish on Hugging Face and **paste the public post URL below**. **Video (optional):** paste YouTube URL below. **Slides:** paste URL below. |
| **Environment on Hugging Face Spaces** (discoverable, runnable) | **Submit this Space URL to organizers:** [META_HACKATHON_FINALE](https://huggingface.co/spaces/Aditya9605/META_HACKATHON_FINALE) · **Live app:** [aditya9605-meta-hackathon-finale.hf.space](https://aditya9605-meta-hackathon-finale.hf.space) |
| **README** motivates the problem, explains the env, shows results, and links **Space + all extra materials** | This file |

**Paste your published materials here (team leader):**

- **HF mini-blog / model card / Discussion URL:** _(add after publishing — do not replace the in-repo `outputs/hf_blog_post.md`; keep that as source)_
- **YouTube (under two minutes) URL:** _(optional)_
- **Slides / deck URL:** _(optional)_

**Judging guide (“what judges look for”):** [OpenEnv Hackathon — judge notes (Google Doc)](https://docs.google.com/document/d/1Odznuzwtb1ecDOm2t6ToZd4MuMXXfO6vWUGcxbC6mFs/edit?tab=t.0#bookmark=kix.2dz0x0nie3me)

### NOTE 2 — Portal rules

- **Only one submission per team** (pick your best project).
- Submit the **Hugging Face Space URL**; judges pull the environment from that link.
- **Only the team leader’s submission is accepted** for the team.
- **Changes after the official deadline may not be considered** — freeze and tag a release if your platform allows.

## Links for Judges

- **Hugging Face Space (canonical — only Space for this project):** [META_HACKATHON_FINALE on the Hub](https://huggingface.co/spaces/Aditya9605/META_HACKATHON_FINALE) · live app: [aditya9605-meta-hackathon-finale.hf.space](https://aditya9605-meta-hackathon-finale.hf.space)
- API docs: [Space /docs](https://aditya9605-meta-hackathon-finale.hf.space/docs)
- Interactive dashboard: [Space /web](https://aditya9605-meta-hackathon-finale.hf.space/web)
- **GitHub repo:** [Raje0906/META_HACKATHON](https://github.com/Raje0906/META_HACKATHON) (full source, eval plots, and training scripts)
- W&B (training loss / reward / KL, etc.): [soc-simulator-grpo](https://wandb.ai/rajeaditya999-/soc-simulator-grpo)
- In-repo writeup draft: [`outputs/hf_blog_post.md`](outputs/hf_blog_post.md)
- Demo pitch: [`hackathon_pitch.md`](hackathon_pitch.md)

## Minimum Requirement Checklist (Hackathon)

- OpenEnv latest-compatible environment: `openenv.yaml` + FastAPI server in `server/app.py`.
- **Training (TRL / Unsloth, Colab-ready):**
  - Canonical all-in-one GRPO script: `training/colab_grpo_all_in_one.py`
  - Also: `training/colab_unsloth_grpo.py`, `training/colab_unsloth_ppo.py`
- **Evidence of training** (committed under `outputs/evals/` on **GitHub**; HF Space git may omit PNG binaries):
  - `scores.json`
  - `reward_curve_baseline_vs_trained.png`
  - `red_vs_blue_curve.png`
- Environment hosted on Hugging Face Space: [live Space](https://aditya9605-meta-hackathon-finale.hf.space)
- README motivates the problem, explains the env, and links Space + blog/video/slides (this file).
- Rebuild plots from existing JSON without re-hitting the API: `python training/red_vs_blue_loop.py --plots-only`

### Training progress (baseline vs trained)

![Baseline vs trained blue scores and red evasion](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/red_vs_blue_curve.png)

*Smoothed per-episode scores from `training/red_vs_blue_loop.py`; raw numbers in `outputs/evals/scores.json`.*

If the image above does not load immediately after a push, use the copy in the repo: [`outputs/evals/red_vs_blue_curve.png`](outputs/evals/red_vs_blue_curve.png).

**Note:** Hugging Face Spaces git hooks reject binary PNGs in the Space repository. This repo’s **GitHub** branch `hf-final` keeps the plot files for judges; the Space deploy uses the same code and `scores.json` with README figures loaded from GitHub `raw.githubusercontent.com`.

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

These aggregates match the latest committed `outputs/evals/scores.json` (50 episodes per task in that file’s metadata). Re-run `training/red_vs_blue_loop.py` to refresh after environment or policy changes.

## Reward Design and Anti-Hacking Safeguards

- Multiple signals: step reward + terminal grading + final score deltas.
- Penalties for false positives, redundant actions, unnecessary ignore, and missed threats.
- Early completion bonus to favor decisive mitigation over passive looping.
- Schema drift support (`source_ip`/`src_addr`/`remote_ip` and user key variants) to reduce brittle shortcuts.
- Deterministic graders (`graders/`) used as verifiable reward sources.

## Minimal Training Scripts (Hackathon Requirement)

- **GRPO + Unsloth (recommended Colab entrypoint):** `training/colab_grpo_all_in_one.py`
- GRPO + Unsloth (alternate): `training/colab_unsloth_grpo.py`
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
