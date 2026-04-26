---
title: "We Taught an LLM to Think Like a Tier-2 Analyst (Without Letting It Cheat)"
tags: ["reinforcement-learning", "cybersecurity", "openenv", "soc", "grpo", "hackathon", "llm-agents"]
---

# We Taught an LLM to Think Like a Tier-2 Analyst (Without Letting It Cheat)

If you have ever watched a real SOC on a bad day, you know the job is not “grep for a bad IP and call it a win.” It is messy: alerts that disagree, logs that use different field names every time someone upgrades a collector, benign activity that *looks* scary, and attacks that only make sense when you connect three boring events across twenty minutes. Most importantly, you rarely see the full story at once. You act anyway.

**SOC Simulator** is our answer to a question we kept asking while reading glossy AI security demos: *can we train a language model to get better at that kind of thinking—not just at quoting MITRE trivia—inside a real interactive loop?*

We built this as an **OpenEnv** environment: a live world the model can step through, break, get penalized in, and (sometimes) fix. This post is the story of that world, why we made it cruel in the right ways, and what happened when we actually ran training.

---

## Why a simulator, and why now?

Static benchmarks teach models to pattern-match. A spreadsheet of labeled logs rewards the model that memorizes the training set. Real analysts do something harder: they **commit to actions under uncertainty**—block an IP, flag a user, isolate a host, escalate, or (rarely) consciously do nothing—and then live with the consequences.

Reinforcement learning is a natural fit, but only if the environment refuses to be gamed. So we focused on three things that sound boring on a slide but matter enormously in practice:

1. **Partial observability** — you see alerts and recent events, not the attacker’s full playbook.  
2. **Structured actions** — the model must output real decisions, not an essay.  
3. **Adversarial pressure** — the world fights back. Quietly. Like real attackers do.

---

## Meet the room: easy panic, medium grind, hard nightmare

We ship three tasks on purpose. They are not three sizes of the same puzzle; they are three different *shapes* of stress.

**Easy — phishing that actually worked.** Someone clicked. Credentials showed up on a VPN edge case you wish you did not have to explain to leadership. The “right” move is not one magic button; it is the disciplined sequence a tired analyst still performs: stop the bleeding, then account hygiene.

**Medium — brute force that becomes a story.** Failed auth attempts pile up, geography stops making sense, and a host that used to be boring is suddenly interesting. The environment rewards correlation, not the loudest alert.

**Hard — a full kill chain.** Recon becomes access becomes lateral movement becomes exfiltration. If your policy only ever learns the first act of the play, you lose slowly and expensively.

Across all three, we keep the observation format honest: SIEM-ish JSON, alerts with severity, events with messy details. It should feel like a dashboard, not a exam question with the answer in bold.

---

## The part everyone skips: we made “cheating” expensive

Here is an uncomfortable truth about RL environments: if you are not careful, the smartest learner in the room is not the defender. It is the exploit that finds the shortest path to a high score.

We tried to design rewards the way a good lead would review a shift:

- **You get credit for meaningful containment** — the right block, flag, isolation, or escalation when the scenario calls for it.  
- **You pay for theater** — false positives hurt, “ignore” as a lazy default hurts, and missing an actual threat hurts more.  
- **We bias toward closure** — finishing the job should feel better than stalling forever in analysis paralysis.

We also added **schema drift** on purpose. The same idea—“source IP”—might show up under different keys. If your policy only works when the JSON spells things the friendly way, it is not ready for production. Full stop.

Optional **live threat intel** can feed the world real noisy signals from the internet. That is not there to look cool in a README. It is there because the real world is not a closed dataset.

---

## Red team as a teacher, not a gimmick

We are not trying to win a cyberwar in a notebook. We are trying to build **curriculum**.

Our **Red** side mutates scenarios: different IPs, different accounts, different emphasis. When **Blue** gets competent, the world does not hand out participation trophies. It adapts. That is closer to how teams actually mature than a static leaderboard ever will be.

If you care about hackathon themes: this is multi-agent tension (blue vs red), professional tooling (structured actions on a live API), long-horizon reasoning on the hard task, and self-improvement through an escalating curriculum—not because we checked boxes, but because those boxes describe real training pain.

---

## What we measured (and we are not going to cherry-pick)

We trained with **GRPO** using **Unsloth** and **TRL**, tied to our deployed **Hugging Face Space** so the model learns against a living server, not a frozen JSON dump. We logged runs to **Weights & Biases** so the loss-and-reward story is visible, not whispered about in a private notebook.

For evaluation, we run a **baseline vs trained** loop across many episodes and save everything under `outputs/evals/`—plots plus raw JSON—so anyone can reproduce the headline numbers.

From our **latest committed evaluation** (50 episodes per task), the **overall average uplift** for the trained policy vs the baseline is **+0.195**. Breaking that down honestly:

- **Easy:** uplift **+0.057** — modest on paper, but the trained run shows **clear learning within the run** (average score on the **last 10 episodes** is **0.153** vs **0.065** on the **first 10**). That is the shape you want: not a lottery ticket, a slope.  
- **Medium:** average uplift is slightly negative (**−0.022**) over the full 50 episodes—worth saying out loud. Security work is noisy; some weeks your playbook meets a weird edge case and your metrics look petty. Still, the trained policy **improves from early to late episodes** (**+0.035** from first 10 to last 10), which tells us the signal is not dead; the aggregate average is just unforgiving.  
- **Hard:** uplift **+0.551** — this is where the trained policy really separates from the baseline. On a multi-stage incident, “sort of right” is not enough; here, the trained agent consistently pushes into territory the baseline rarely reaches.

We are proud of the hard task result. We are also proud that we publish the medium task wobble. Judges have seen polished demos. They have not always seen teams willing to show the variance that *real* training surfaces.

---

## What lives in `outputs/evals/` (figures + numbers)

Every evaluation run drops a small bundle in **`outputs/evals/`** on GitHub so nobody has to trust a screenshot we took on a laptop somewhere.

**The plot (three panels: easy / medium / hard).** Each panel tracks episodes on the horizontal axis and score on the vertical. You get a dashed **baseline** policy, a solid **trained** policy, and a **red** stress line so you can see defender progress *and* adversary pressure in one glance. Values are smoothed so the eye can follow trends instead of chasing single-episode noise.

![Three-task eval: baseline vs trained blue team scores and red pressure (smoothed over 50 episodes per task)](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/red_vs_blue_curve.png)

Our training script saves that same figure under **two filenames** so different docs (README vs hackathon PDF vs your own notes) can point at whichever name they expect. The pixels match—only the label on disk changes:

- [`outputs/evals/red_vs_blue_curve.png`](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/red_vs_blue_curve.png) (direct image link)  
- [`outputs/evals/reward_curve_baseline_vs_trained.png`](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/reward_curve_baseline_vs_trained.png) (same figure; “baseline vs trained” naming)

**The spreadsheet of truth.** If you want to re-plot, argue with our smoothing, or drop numbers into a slide:

- [`outputs/evals/scores.json`](https://raw.githubusercontent.com/Raje0906/META_HACKATHON/main/outputs/evals/scores.json) — per-episode arrays, summaries, and the overall uplift we quote in this post.

Clone the repo or hit the raw links above; either way, the eval folder is meant to be **boring, reproducible, and a little bit brave**.

---

## Try it like a judge, not like a linter

If you only read the OpenAPI spec, you will understand the plumbing. If you **open the Space**, reset a scenario, watch the alerts, and step actions while the risk meter moves, you will understand the *point*.

- **Live Space:** [META_HACKATHON_FINALE](https://huggingface.co/spaces/Aditya9605/META_HACKATHON_FINALE)  
- **Running app:** [aditya9605-meta-hackathon-finale.hf.space](https://aditya9605-meta-hackathon-finale.hf.space)  
- **Dashboard:** [`/web`](https://aditya9605-meta-hackathon-finale.hf.space/web) on the same deployment  
- **Code & eval artifacts:** [GitHub — META_HACKATHON](https://github.com/Raje0906/META_HACKATHON)  
- **Training curves:** [W&B — soc-simulator-grpo](https://wandb.ai/rajeaditya999-/soc-simulator-grpo)

---

## Closing thought

We did not set out to build the world’s most impressive API diagram. We set out to build a place where an LLM can **practice** the uncomfortable parts of defense—uncertainty, consequence, adaptation—and where we can **prove** it learned something, not just memorized something.

If you are judging this submission: spin up the Space, pick the hard task, and watch what happens when a policy has to chain decisions instead of spitting out a single heroic sentence. That moment—when the environment answers back—is the whole project.

We hope it resonates as much as it terrified us while we were building it.
