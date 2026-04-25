"""
SOC Simulator - Baseline vs Trained evaluation loop.

Produces:
  - outputs/evals/scores.json
  - outputs/evals/red_vs_blue_curve.png
  - outputs/evals/reward_curve_baseline_vs_trained.png
"""
import datetime
import json
import os
import random
import time
from collections import Counter, defaultdict

import matplotlib.pyplot as plt
import numpy as np
import requests
from tqdm import tqdm

BASE_URL = "https://aditya9605-meta-hackathon-finale.hf.space"
EPISODES = 50
TASKS = ["easy_phishing_login", "medium_brute_force_geo", "hard_apt_multistage"]
WARMUP_TIMEOUT = 60

Q_TABLE = defaultdict(lambda: defaultdict(float))
Q_ALPHA = 0.1
ALL_ACTIONS = ["block_ip", "flag_user", "isolate_host", "escalate_alert", "ignore"]
IP_KEYS = ("remote_ip", "source_ip", "src_addr")
USER_KEYS = ("account_name", "user_id", "username")


def warmup_space(base_url):
    print("Waking up HF Space...")
    start = time.time()
    while time.time() - start < WARMUP_TIMEOUT:
        try:
            r = requests.get(f"{base_url}/health", timeout=10)
            if r.status_code == 200:
                print("HF Space is awake")
                return True
        except Exception:
            pass
        time.sleep(3)
    print("WARNING: HF Space did not respond. Continuing anyway.")
    return False


def get_q_best_action(task_id):
    q_row = Q_TABLE[task_id]
    if not q_row:
        return None
    return max(q_row, key=q_row.get)


def _get_first(event, keys):
    for key in keys:
        if event.get(key):
            return event.get(key)
    return None


def _extract_threat_targets(obs):
    alerts = obs.get("active_alerts", [])
    events = obs.get("recent_events", [])
    sorted_alerts = sorted(alerts, key=lambda a: float(a.get("anomaly_score", 0)), reverse=True)
    threat_ips, threat_users, threat_hosts = [], [], []

    for alert in sorted_alerts:
        lvl = alert.get("threat_level", "").lower()
        if lvl not in ("high", "critical"):
            continue
        for evt_id in alert.get("related_events", []):
            for e in events:
                if e.get("event_id") != evt_id:
                    continue
                src = _get_first(e, IP_KEYS)
                uid = _get_first(e, USER_KEYS)
                hid = e.get("host_id")
                if src and src not in threat_ips:
                    threat_ips.append(src)
                if uid and uid not in threat_users:
                    threat_users.append(uid)
                if hid and hid not in threat_hosts:
                    threat_hosts.append(hid)

    # Fallback for schema drift cases where alert related event mapping is weak.
    for e in events:
        src = _get_first(e, IP_KEYS)
        uid = _get_first(e, USER_KEYS)
        details = e.get("details", {}) or {}
        country = (e.get("country") or "").upper()
        event_kind = (e.get("event_type") or e.get("evt_category") or e.get("log_type") or "").lower()

        suspicious = bool(details.get("risk_signal")) or bool(details.get("mfa_bypassed")) or country not in ("US", "")
        suspicious = suspicious or any(token in event_kind for token in ("phishing", "lateral", "data_exfil", "malware"))

        if suspicious and src and src not in threat_ips:
            threat_ips.append(src)
        if suspicious and uid and uid not in threat_users:
            threat_users.append(uid)
        if suspicious and e.get("host_id") and e.get("host_id") not in threat_hosts:
            threat_hosts.append(e.get("host_id"))

    return threat_ips, threat_users, threat_hosts


def random_baseline_agent(obs, *_):
    events = obs.get("recent_events", [])
    ips = list({_get_first(e, IP_KEYS) for e in events if _get_first(e, IP_KEYS)})
    users = list({_get_first(e, USER_KEYS) for e in events if _get_first(e, USER_KEYS)})
    hosts = list({e.get("host_id") for e in events if e.get("host_id")})

    atype = random.choice(ALL_ACTIONS)
    target = None
    if atype == "block_ip" and ips:
        target = random.choice(ips)
    elif atype == "flag_user" and users:
        target = random.choice(users)
    elif atype == "isolate_host" and hosts:
        target = random.choice(hosts)
    elif atype == "escalate_alert":
        target = "system"
    return {"action_type": atype, "target": target}


def epsilon_heuristic_agent(obs, episode_num, task_id):
    epsilon = max(0.05, 0.4 * (0.93 ** episode_num))
    threat_ips, threat_users, threat_hosts = _extract_threat_targets(obs)
    all_hosts = list({e.get("host_id") for e in obs.get("recent_events", []) if e.get("host_id")})

    if random.random() < epsilon:
        if task_id == "easy_phishing_login":
            action_pool = ["block_ip", "flag_user", "block_ip", "flag_user", "escalate_alert", "ignore"]
        elif task_id == "medium_brute_force_geo":
            action_pool = ["block_ip", "flag_user", "isolate_host", "block_ip", "ignore", "escalate_alert"]
        else:
            action_pool = ALL_ACTIONS
        atype = random.choice(action_pool)
        target = "system"
        if atype == "block_ip" and threat_ips:
            target = random.choice(threat_ips)
        elif atype == "flag_user" and threat_users:
            target = random.choice(threat_users)
        elif atype == "isolate_host" and (threat_hosts or all_hosts):
            target = random.choice(threat_hosts or all_hosts)
        return {"action_type": atype, "target": target}

    alerts = obs.get("active_alerts", [])
    state = obs.get("system_state", {})
    isolated = state.get("isolated_hosts", [])
    blocked = state.get("blocked_ips", [])
    flagged = state.get("flagged_users", [])
    unresolved_ips = [ip for ip in threat_ips if ip not in blocked]
    unresolved_users = [u for u in threat_users if u not in flagged]
    unresolved_hosts = [h for h in threat_hosts if h not in isolated]

    # Priority gating for easy task: block -> flag -> (optional) escalate.
    if task_id == "easy_phishing_login":
        if unresolved_ips:
            return {"action_type": "block_ip", "target": unresolved_ips[0]}
        if unresolved_users:
            return {"action_type": "flag_user", "target": unresolved_users[0]}
        if float(obs.get("network_anomaly_score", 0)) > 0.8:
            return {"action_type": "escalate_alert", "target": "system"}
        return {"action_type": "ignore", "target": None}

    candidates = []
    for ip in unresolved_ips:
        candidates.append({"action_type": "block_ip", "target": ip})
    for user in unresolved_users:
        candidates.append({"action_type": "flag_user", "target": user})
    for a in alerts:
        if a.get("threat_level", "").lower() == "critical":
            for h in unresolved_hosts:
                candidates.append({"action_type": "isolate_host", "target": h})

    allow_escalate = float(obs.get("network_anomaly_score", 0)) > 0.8 and (
        not unresolved_ips or not unresolved_users or not unresolved_hosts
    )
    if allow_escalate:
        candidates.append({"action_type": "escalate_alert", "target": "system"})

    if candidates:
        q_row = Q_TABLE[task_id]
        # Prefer action type quality first, then Q score.
        pri = {"block_ip": 4, "flag_user": 3, "isolate_host": 3, "escalate_alert": 2, "ignore": 1}
        return max(candidates, key=lambda c: (pri.get(c["action_type"], 0), q_row.get(c["action_type"], 0.0)))
    return {"action_type": "ignore", "target": None}


def run_episode(base_url, task_id, episode_num, policy_fn):
    action_stats = defaultdict(lambda: {"count": 0, "reward_sum": 0.0})
    try:
        r = requests.post(
            f"{base_url}/reset",
            json={"task_id": task_id, "custom_params": {"enable_red_agent": True, "use_live_threat_intel": True}},
            timeout=20,
        )
        if r.status_code != 200:
            return 0.0, 0.0, 0, action_stats

        obs = r.json().get("observation", r.json())
        max_steps = 5 if "easy" in task_id else (8 if "medium" in task_id else 15)
        done, steps = False, 0

        while not done and steps < max_steps:
            action = policy_fn(obs, episode_num, task_id)
            action_stats[action["action_type"]]["count"] += 1
            sr = requests.post(
                f"{base_url}/step",
                json={"action": {"action_type": action["action_type"], "target": action.get("target")}},
                timeout=20,
            )
            if sr.status_code != 200:
                break
            sdata = sr.json()
            step_reward = float(sdata.get("reward", sdata.get("observation", {}).get("reward", 0.0)))
            action_stats[action["action_type"]]["reward_sum"] += step_reward
            obs = sdata.get("observation", sdata)
            done = obs.get("done", False)
            steps += 1

        gr = requests.get(f"{base_url}/score", timeout=10)
        if gr.status_code == 200:
            score_data = gr.json()
            return float(score_data.get("score", 0.0)), float(score_data.get("red_score", 0.0)), steps, action_stats
        return 0.0, 0.0, steps, action_stats
    except Exception:
        return 0.0, 0.0, 0, action_stats


def update_q_table(task_id, action_stats, final_reward):
    if not action_stats:
        return
    total = sum(v["count"] for v in action_stats.values())
    for action_type, stats in action_stats.items():
        count = stats["count"]
        step_avg = stats["reward_sum"] / max(count, 1)
        target_value = 0.7 * step_avg + 0.3 * final_reward
        if task_id == "easy_phishing_login" and action_type in ("ignore", "escalate_alert"):
            target_value -= 0.08
        if task_id == "medium_brute_force_geo" and action_type == "ignore":
            target_value -= 0.03
        weight = count / max(total, 1)
        current_q = Q_TABLE[task_id][action_type]
        Q_TABLE[task_id][action_type] = current_q + (Q_ALPHA * weight) * (target_value - current_q)
    dominant_action = max(action_stats.items(), key=lambda kv: kv[1]["count"])[0]
    current_q = Q_TABLE[task_id][dominant_action]
    Q_TABLE[task_id][dominant_action] = current_q + Q_ALPHA * (final_reward - current_q)


def smooth(y, box_pts):
    if len(y) < box_pts:
        return np.array(y)
    box = np.ones(box_pts) / box_pts
    y_pad = np.pad(y, (box_pts // 2, box_pts // 2), mode="edge")
    y_smooth = np.convolve(y_pad, box, mode="valid")
    return y_smooth[: len(y)]


def _avg(arr):
    return float(sum(arr) / len(arr)) if arr else 0.0


def main():
    os.makedirs("outputs/evals", exist_ok=True)
    warmup_space(BASE_URL)
    all_results = {}

    for task in TASKS:
        print(f"\nEvaluating task: {task}")
        baseline_blue_scores, baseline_red_scores = [], []
        trained_blue_scores, trained_red_scores = [], []

        for ep in tqdm(range(1, EPISODES + 1)):
            b_blue, b_red, _, _ = run_episode(BASE_URL, task, ep, random_baseline_agent)
            t_blue, t_red, _, action_stats = run_episode(BASE_URL, task, ep, epsilon_heuristic_agent)
            update_q_table(task, action_stats, t_blue)

            baseline_blue_scores.append(b_blue)
            baseline_red_scores.append(b_red)
            trained_blue_scores.append(t_blue)
            trained_red_scores.append(t_red)

            if ep % 10 == 0:
                print(
                    f"  Ep {ep}: baseline={_avg(baseline_blue_scores[-10:]):.3f} | "
                    f"trained={_avg(trained_blue_scores[-10:]):.3f} | q_best={get_q_best_action(task)}"
                )

        all_results[task] = {
            "baseline_blue_scores": baseline_blue_scores,
            "baseline_red_scores": baseline_red_scores,
            "trained_blue_scores": trained_blue_scores,
            "trained_red_scores": trained_red_scores,
        }

    out_obj = {
        "metadata": {
            "episodes": EPISODES,
            "tasks": TASKS,
            "timestamp": datetime.datetime.now().isoformat(),
            "base_url": BASE_URL,
            "evaluation_type": "baseline_vs_trained",
        },
        "results": all_results,
        "q_table": {task: dict(Q_TABLE[task]) for task in TASKS},
        "summary": {},
    }

    global_uplifts = []
    for t in TASKS:
        base = all_results[t]["baseline_blue_scores"]
        train = all_results[t]["trained_blue_scores"]
        base_avg = _avg(base)
        train_avg = _avg(train)
        uplift = train_avg - base_avg
        global_uplifts.append(uplift)
        out_obj["summary"][t] = {
            "baseline_avg": round(base_avg, 3),
            "trained_avg": round(train_avg, 3),
            "uplift_avg": round(uplift, 3),
            "trained_first10_avg": round(_avg(train[:10]), 3),
            "trained_last10_avg": round(_avg(train[-10:]), 3),
            "trained_improvement": round(_avg(train[-10:]) - _avg(train[:10]), 3),
            "q_best_action": get_q_best_action(t),
            "red_peak_trained": round(max(all_results[t]["trained_red_scores"]) if all_results[t]["trained_red_scores"] else 0.0, 3),
        }

    out_obj["overall"] = {
        "mean_uplift_vs_baseline": round(_avg(global_uplifts), 3),
        "mean_trained_score": round(_avg([out_obj["summary"][t]["trained_avg"] for t in TASKS]), 3),
        "mean_baseline_score": round(_avg([out_obj["summary"][t]["baseline_avg"] for t in TASKS]), 3),
    }

    with open("outputs/evals/scores.json", "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2)

    plt.style.use("seaborn-v0_8-darkgrid")
    fig, axs = plt.subplots(1, 3, figsize=(18, 5))
    titles = {
        "easy_phishing_login": "Phishing login [easy]",
        "medium_brute_force_geo": "Brute force + geo [medium]",
        "hard_apt_multistage": "APT kill chain [hard]",
    }
    for idx, t in enumerate(TASKS):
        ax = axs[idx]
        x = np.arange(1, EPISODES + 1)
        base = np.array(all_results[t]["baseline_blue_scores"])
        train = np.array(all_results[t]["trained_blue_scores"])
        red = np.array(all_results[t]["trained_red_scores"])

        ax.plot(x, smooth(base, 7), "--", color="#6b7280", linewidth=2, label="Baseline blue score" if idx == 0 else "")
        ax.plot(x, smooth(train, 7), "-", color="#2563eb", linewidth=2.5, label="Trained blue score" if idx == 0 else "")
        ax.plot(x, smooth(red, 7), "-", color="#dc2626", linewidth=2, alpha=0.85, label="Red evasion rate" if idx == 0 else "")
        ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.4)
        ax.set_ylim(-0.05, 1.05)
        ax.set_xlim(1, EPISODES)
        ax.set_title(titles[t])
        ax.set_xlabel("Episode")
        if idx == 0:
            ax.set_ylabel("Score")

    fig.legend(loc="lower center", ncol=3, bbox_to_anchor=(0.5, -0.04))
    fig.suptitle("SOC Simulator - Baseline vs Trained (Blue) and Red Evasion", fontsize=14, fontweight="bold")
    plt.tight_layout(rect=[0, 0.04, 1, 0.95])
    plt.savefig("outputs/evals/reward_curve_baseline_vs_trained.png", dpi=150, bbox_inches="tight")
    plt.savefig("outputs/evals/red_vs_blue_curve.png", dpi=150, bbox_inches="tight")

    print("\n================================================")
    print("SOC SIMULATOR - BASELINE VS TRAINED SUMMARY")
    print("================================================")
    print(f"{'Task':<25} {'Baseline':<10} {'Trained':<10} {'Uplift':<10} {'Q-Best'}")
    for t in TASKS:
        s = out_obj["summary"][t]
        print(f"{t:<25} {s['baseline_avg']:<10.3f} {s['trained_avg']:<10.3f} {s['uplift_avg']:<10.3f} {s['q_best_action']}")
    print("------------------------------------------------")
    print(f"Mean uplift vs baseline: {out_obj['overall']['mean_uplift_vs_baseline']:+.3f}")
    print("Graphs saved:")
    print("  outputs/evals/reward_curve_baseline_vs_trained.png")
    print("  outputs/evals/red_vs_blue_curve.png")
    print("Data saved: outputs/evals/scores.json")
    print("================================================")


if __name__ == "__main__":
    main()
