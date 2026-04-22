"""
SOC Simulator - Red vs Blue Agent Training Loop

Features:
  - Q-table learning: maps (task_id, action_type) → Q-value
  - Real red scores pulled from the server /score endpoint
  - Epsilon-greedy exploration with Q-guided exploitation
"""
import os
import time
import json
import random
import datetime
import requests
import numpy as np
import matplotlib.pyplot as plt
from tqdm import tqdm
from collections import defaultdict, Counter

BASE_URL = "https://aditya9605-meta-hackathon-finale.hf.space"
EPISODES = 50
TASKS = ["easy_phishing_login", "medium_brute_force_geo", "hard_apt_multistage"]
WARMUP_TIMEOUT = 60

# ── Q-Table ─────────────────────────────────────────────────────────────────
# Maps (task_id, action_type) → Q-value
# Updated after each episode using the final blue score as reward signal
Q_TABLE = defaultdict(lambda: defaultdict(float))
Q_ALPHA = 0.1  # Learning rate

ALL_ACTIONS = ["block_ip", "flag_user", "isolate_host", "escalate_alert", "ignore"]


def warmup_space(base_url):
    """Ping /health until 200 or timeout. HF free tier sleeps."""
    print("Waking up HF Space...")
    start = time.time()
    while time.time() - start < WARMUP_TIMEOUT:
        try:
            r = requests.get(f"{base_url}/health", timeout=10)
            if r.status_code == 200:
                print("HF Space is awake")
                return True
        except:
            pass
        time.sleep(3)
    print("WARNING: HF Space did not respond. Continuing anyway.")
    return False


def get_q_best_action(task_id):
    """Return the action_type with the highest Q-value for this task."""
    q_row = Q_TABLE[task_id]
    if not q_row:
        return None
    return max(q_row, key=q_row.get)


def epsilon_heuristic_agent(obs, episode_num, task_id):
    """
    Epsilon-greedy agent with Q-guided exploitation.
    
    Exploration (random) decays from 0.4 → 0.05 via epsilon = max(0.05, 0.4 * 0.93^ep).
    Exploitation uses a heuristic decision tree, but the heuristic priority
    is biased toward the action_type with the highest Q-value for this task.
    """
    epsilon = max(0.05, 0.4 * (0.93 ** episode_num))
    
    ips, users, hosts = [], [], []
    for e in obs.get("recent_events", []):
        if e.get("source_ip"): ips.append(e.get("source_ip"))
        if e.get("user_id"): users.append(e.get("user_id"))
        if e.get("host_id"): hosts.append(e.get("host_id"))
        if "details" in e and isinstance(e["details"], dict):
            if "host" in e["details"]: hosts.append(e["details"]["host"])
            
    for a in obs.get("active_alerts", []):
        if a.get("source_ip"): ips.append(a.get("source_ip"))
        if a.get("user_id"): users.append(a.get("user_id"))
        if a.get("host_id"): hosts.append(a.get("host_id"))

    ips = list(set(ips))
    users = list(set(users))
    hosts = list(set(hosts))
    
    if random.random() < epsilon:
        # Exploration — uniform random action
        atype = random.choice(ALL_ACTIONS)
        target = "unknown"
        if atype == "block_ip" and ips: target = random.choice(ips)
        elif atype == "flag_user" and users: target = random.choice(users)
        elif atype == "isolate_host" and hosts: target = random.choice(hosts)
        elif atype == "escalate_alert" and ips: target = random.choice(ips)
        return {"action_type": atype, "target": target}
    else:
        # Exploitation — Q-guided heuristic
        alerts = obs.get("active_alerts", [])
        events = obs.get("recent_events", [])
        state = obs.get("system_state", {})
        isolated = state.get("isolated_hosts", [])
        blocked = state.get("blocked_ips", [])
        flagged = state.get("flagged_users", [])
        
        # Build candidate actions from the heuristic rules
        candidates = []
        
        # 1. Critical alert -> isolate_host on affected_host
        for a in alerts:
            if a.get("threat_level", "").lower() == "critical":
                target = hosts[0] if hosts else "WORKSTATION-01"
                for h in hosts:
                    if h in a.get("description", "") or h in a.get("title", ""): target = h
                if target not in isolated:
                    candidates.append({"action_type": "isolate_host", "target": target})
                
        # 2. High severity alert -> block_ip on source_ip
        for a in alerts:
            if a.get("threat_level", "").lower() == "high":
                target = ips[-1] if ips else "1.1.1.1"
                for i in ips:
                    if i in a.get("description", "") or i in a.get("title", ""): target = i
                if target not in blocked:
                    candidates.append({"action_type": "block_ip", "target": target})
                
        # 3. geo_anomaly or mfa_bypassed event -> flag_user
        for e in events:
            det = e.get("details", {})
            if det.get("mfa_bypassed") or det.get("risk_signal") == "impossible_travel" or "geo_anomaly" in str(det):
                target = e.get("user_id", users[0] if users else "admin")
                if target not in flagged:
                    candidates.append({"action_type": "flag_user", "target": target})
                
        # 4. network_anomaly_score > 0.8 -> escalate_alert
        for e in events:
            det = e.get("details", {})
            if float(det.get("network_anomaly_score", 0)) > 0.8:
                target = e.get("source_ip", ips[0] if ips else "network")
                candidates.append({"action_type": "escalate_alert", "target": target})
        
        # If we have candidate actions, pick the one whose action_type has 
        # the highest Q-value for this task 
        if candidates:
            q_row = Q_TABLE[task_id]
            best = max(candidates, key=lambda c: q_row.get(c["action_type"], 0.0))
            return best
                
        # 5. default — nothing actionable
        return {"action_type": "ignore", "target": "system"}


def run_episode(base_url, task_id, episode_num):
    """
    Run one full episode against the server.
    Returns (blue_score, red_score, steps, action_counts).
    """
    action_counts = Counter()
    try:
        r = requests.post(
            f"{base_url}/reset",
            json={
                "task_id": task_id,
                "custom_params": {"enable_red_agent": True, "use_live_threat_intel": True}
            },
            timeout=15
        )
        if r.status_code != 200:
            return 0.0, 0.0, 0, action_counts
            
        data = r.json()
        obs = data.get("observation", data)
        
        max_steps = 15
        if "easy" in task_id: max_steps = 5
        elif "medium" in task_id: max_steps = 8
        
        done = False
        steps = 0
        
        while not done and steps < max_steps:
            action = epsilon_heuristic_agent(obs, episode_num, task_id)
            action_counts[action["action_type"]] += 1
            sr = requests.post(
                f"{base_url}/step",
                json={"action": {"action_type": action["action_type"], "target": action["target"]}},
                timeout=15
            )
            if sr.status_code != 200:
                break
            
            sdata = sr.json()
            obs = sdata.get("observation", sdata)
            done = obs.get("done", False)
            steps += 1
            
        # Get REAL scores from the server
        gr = requests.get(f"{base_url}/score", timeout=10)
        if gr.status_code == 200:
            score_data = gr.json()
            blue_score = float(score_data.get("score", 0.0))
            red_score = float(score_data.get("red_score", 0.0))
        else:
            blue_score = 0.0
            red_score = 0.0
        
        return blue_score, red_score, steps, action_counts
    except Exception as e:
        return 0.0, 0.0, 0, action_counts


def update_q_table(task_id, action_counts, reward):
    """
    Update Q-table after each episode.
    
    The dominant action (most frequently chosen) in the episode gets
    its Q-value updated using the final blue score as the reward signal:
        Q[task][action] = Q[task][action] + alpha * (reward - Q[task][action])
    
    We also do a smaller update for all actions taken, proportional to their
    frequency, so the Q-table learns from the full action distribution.
    """
    if not action_counts:
        return
    
    # Update ALL actions taken, weighted by frequency
    total = sum(action_counts.values())
    for action_type, count in action_counts.items():
        weight = count / total  # Frequency-proportional weight
        current_q = Q_TABLE[task_id][action_type]
        # Full alpha for the dominant action, scaled alpha for others
        effective_alpha = Q_ALPHA * weight
        Q_TABLE[task_id][action_type] = current_q + effective_alpha * (reward - current_q)
    
    # Extra boost for the dominant action (most frequently chosen)
    dominant_action = action_counts.most_common(1)[0][0]
    current_q = Q_TABLE[task_id][dominant_action]
    Q_TABLE[task_id][dominant_action] = current_q + Q_ALPHA * (reward - current_q)


def smooth(y, box_pts):
    """Simple moving average convolution mapping identically over sequence length"""
    if len(y) < box_pts:
        return np.array(y)
    box = np.ones(box_pts)/box_pts
    y_pad = np.pad(y, (box_pts//2, box_pts//2), mode='edge')
    y_smooth = np.convolve(y_pad, box, mode='valid')
    if len(y_smooth) > len(y):
        y_smooth = y_smooth[:len(y)]
    elif len(y_smooth) < len(y):
        y_smooth = np.pad(y_smooth, (0, len(y)-len(y_smooth)), mode='edge')
    return y_smooth


def main():
    os.makedirs("outputs/evals", exist_ok=True)
    warmup_space(BASE_URL)
    
    all_results = {}
    
    for task in TASKS:
        print(f"\nTraining on task: {task}")
        blue_scores = []
        red_scores = []
        
        for ep in tqdm(range(1, EPISODES + 1)):
            eps = max(0.05, 0.4 * (0.93 ** ep))
            blue_score, red_score, steps, action_counts = run_episode(BASE_URL, task, ep)
            
            # Q-table update using the blue score as reward signal
            update_q_table(task, action_counts, blue_score)
            
            blue_scores.append(blue_score)
            red_scores.append(red_score)
            
            if ep % 10 == 0:
                avg = sum(blue_scores[-10:]) / 10
                q_best = get_q_best_action(task)
                q_val = Q_TABLE[task].get(q_best, 0.0) if q_best else 0.0
                print(f"  Ep {ep}: blue={blue_score:.3f} | red={red_score:.3f} | avg_last_10={avg:.3f} | eps={eps:.3f} | Q_best={q_best}({q_val:.3f})")
                
        all_results[task] = {
            "blue_scores": blue_scores,
            "red_scores": red_scores
        }
        
    # Data Save
    out_obj = {
        "metadata": {
            "episodes": EPISODES,
            "tasks": TASKS,
            "timestamp": datetime.datetime.now().isoformat(),
            "base_url": BASE_URL
        },
        "results": all_results,
        "q_table": {task: dict(Q_TABLE[task]) for task in TASKS},
        "summary": {}
    }
    
    for t in TASKS:
        bs = all_results[t]["blue_scores"]
        rs = all_results[t]["red_scores"]
        b_first = sum(bs[:10])/10 if len(bs)>=10 else sum(bs)/len(bs)
        b_last = sum(bs[-10:])/10 if len(bs)>=10 else sum(bs)/len(bs)
        out_obj["summary"][t] = {
            "blue_first10_avg": round(b_first, 3),
            "blue_last10_avg": round(b_last, 3),
            "blue_improvement": round(b_last - b_first, 3),
            "red_peak": round(max(rs) if rs else 0.0, 3),
            "q_best_action": get_q_best_action(t),
        }
        
    with open("outputs/evals/scores.json", "w") as f:
        json.dump(out_obj, f, indent=2)
        
    # Plotting
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, axs = plt.subplots(1, 3, figsize=(18, 5))
    
    fig.suptitle('SOC Simulator — Red vs Blue Agent Training\nOpenEnv Cybersecurity RL Environment', 
                 fontsize=15, fontweight='bold')
                 
    colors = {
        "easy_phishing_login": '#378ADD',
        "medium_brute_force_geo": '#EF9F27',
        "hard_apt_multistage": '#E24B4A'
    }
    
    titles = {
        "easy_phishing_login": "Phishing login [easy]",
        "medium_brute_force_geo": "Brute force + geo [medium]",
        "hard_apt_multistage": "APT kill chain [hard]"
    }

    for idx, t in enumerate(TASKS):
        ax = axs[idx]
        bs = np.array(all_results[t]["blue_scores"])
        rs = np.array(all_results[t]["red_scores"])
        x = np.arange(1, len(bs) + 1)
        
        c_blue = colors[t]
        c_red = '#E24B4A'
        
        ax.plot(x, bs, 'o', color=c_blue, alpha=0.2)
        bs_smooth = smooth(bs, 7)
        ax.plot(x, bs_smooth, '-', color=c_blue, linewidth=2.5, label="Blue agent defense score" if idx==0 else "")
        ax.fill_between(x, bs_smooth, 0, color=c_blue, alpha=0.08)
        
        ax.plot(x, rs, 'o', color=c_red, alpha=0.2)
        rs_smooth = smooth(rs, 7)
        ax.plot(x, rs_smooth, '-', color=c_red, linewidth=2, label="Red agent evasion rate" if idx==0 else "")
        ax.fill_between(x, rs_smooth, 0, color=c_red, alpha=0.06)
        
        # Difficulty escalation markers
        for ep_i in range(1, len(bs)):
            curr_avg = np.mean(bs[max(0, ep_i+1-5):ep_i+1])
            prev_avg = np.mean(bs[max(0, ep_i-5):ep_i]) if ep_i > 0 else 0
            
            if prev_avg <= 0.75 and curr_avg > 0.75:
                # Crossed above 0.75
                ax.axvline(x=ep_i+1, color='green', linestyle='--', alpha=0.7, 
                           label="Difficulty escalation" if idx==0 and 'Difficulty escalation' not in [l.get_label() for l in ax.lines] else "")
                ax.text(ep_i+1.2, 0.05, "Difficulty escalates", rotation=90, fontsize=8, color='darkgreen')
                
        ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label="0.5 baseline" if idx==0 else "")
        ax.axhline(y=1.0, color='green', linestyle=':', alpha=0.5)
        
        ax.set_ylim(-0.05, 1.1)
        ax.set_xlim(1, EPISODES)
        ax.set_title(titles[t])
        ax.set_xlabel("Episode number")
        if idx == 0:
            ax.set_ylabel("Score (0 to 1)")
            
    fig.legend(loc='lower center', ncol=4, bbox_to_anchor=(0.5, -0.05))
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig("outputs/evals/red_vs_blue_curve.png", dpi=150, bbox_inches='tight')
    
    print("\n================================================")
    print("SOC SIMULATOR — TRAINING RESULTS SUMMARY")
    print("================================================")
    print(f"{'Task':<25} {'First 10':<10} {'Last 10':<10} {'Improvement':<12} {'Q-Best Action'}")
    for t in TASKS:
        summ = out_obj["summary"][t]
        imp = summ['blue_improvement']
        sign = "+" if imp >= 0 else ""
        q_best = summ.get('q_best_action', 'N/A')
        print(f"{t:<25} {summ['blue_first10_avg']:<10.3f} {summ['blue_last10_avg']:<10.3f} {sign}{imp:.3f}       {q_best}")
    print("------------------------------------------------")
    print("Q-Table (learned action preferences):")
    for t in TASKS:
        q_row = Q_TABLE[t]
        if q_row:
            sorted_q = sorted(q_row.items(), key=lambda x: x[1], reverse=True)
            q_str = "  ".join(f"{a}={v:.3f}" for a, v in sorted_q)
            print(f"  {t}: {q_str}")
    print("------------------------------------------------")
    print("Graph saved: outputs/evals/red_vs_blue_curve.png")
    print("Data saved:  outputs/evals/scores.json")
    print("================================================")


if __name__ == "__main__":
    main()
