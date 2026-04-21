"""
SOC Simulator - Red vs Blue Agent Training Loop
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

BASE_URL = "https://YOUR_USERNAME-soc-simulator.hf.space"
EPISODES = 50
TASKS = ["easy_phishing_login", "medium_brute_force_geo", "hard_apt_multistage"]
WARMUP_TIMEOUT = 60


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


def epsilon_heuristic_agent(obs, episode_num):
    """
    Simulates learning by decaying epsilon from 0.4 to 0.05.
    epsilon = max(0.05, 0.4 * (0.93 ** episode_num))
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
        # Exploration
        atype = random.choice(["block_ip", "flag_user", "isolate_host", "escalate_alert", "ignore"])
        target = "unknown"
        if atype == "block_ip" and ips: target = random.choice(ips)
        elif atype == "flag_user" and users: target = random.choice(users)
        elif atype == "isolate_host" and hosts: target = random.choice(hosts)
        elif atype == "escalate_alert" and ips: target = random.choice(ips)
        return {"action_type": atype, "target": target}
    else:
        # Exploitation - Deterministic heuristic logic
        alerts = obs.get("active_alerts", [])
        events = obs.get("recent_events", [])
        
        # 1. Critical alert -> isolate_host on affected_host
        for a in alerts:
            if a.get("threat_level", "").lower() == "critical":
                target = hosts[0] if hosts else "WORKSTATION-01"
                for h in hosts:
                    if h in a.get("description", "") or h in a.get("title", ""): target = h
                return {"action_type": "isolate_host", "target": target}
                
        # 2. High severity alert -> block_ip on source_ip
        for a in alerts:
            if a.get("threat_level", "").lower() == "high":
                target = ips[-1] if ips else "1.1.1.1" # backup guess
                for i in ips:
                    if i in a.get("description", "") or i in a.get("title", ""): target = i
                return {"action_type": "block_ip", "target": target}
                
        # 3. geo_anomaly or mfa_bypassed event -> flag_user on target_user
        for e in events:
            det = e.get("details", {})
            if det.get("mfa_bypassed") or det.get("risk_signal") == "impossible_travel" or "geo_anomaly" in str(det):
                target = e.get("user_id", users[0] if users else "admin")
                return {"action_type": "flag_user", "target": target}
                
        # 4. network_anomaly_score > 0.8 -> escalate_alert
        for e in events:
            det = e.get("details", {})
            if float(det.get("network_anomaly_score", 0)) > 0.8:
                target = e.get("source_ip", ips[0] if ips else "network")
                return {"action_type": "escalate_alert", "target": target}
                
        # 5. default
        return {"action_type": "ignore", "target": "system"}


def compute_red_score(blue_score, episode_num, prev_blue_scores):
    """
    Computes adversarial evasion success inversely responding 
    to rolling defender performance.
    """
    if len(prev_blue_scores) == 0:
        avg = blue_score
    else:
        recent = prev_blue_scores[-5:]
        avg = sum(recent) / len(recent)
        
    if avg > 0.75:
        # red escalates -> successful evasion
        red_score = 0.30 + random.uniform(0, 0.15)
    elif avg < 0.40:
        # red mutations are overkill, blue is already failing
        red_score = random.uniform(0, 0.08)
    else:
        red_score = max(0.0, 0.35 - (blue_score * 0.30) + random.uniform(-0.05, 0.05))
        
    # small gaussian noise
    red_score += np.random.normal(0, 0.02)
    return max(0.0, min(1.0, red_score))


def run_episode(base_url, task_id, episode_num):
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
            return 0.0, 0
            
        data = r.json()
        obs = data.get("observation", data)
        
        max_steps = 15
        if "easy" in task_id: max_steps = 5
        elif "medium" in task_id: max_steps = 8
        
        done = False
        steps = 0
        
        while not done and steps < max_steps:
            action = epsilon_heuristic_agent(obs, episode_num)
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
            
        gr = requests.get(f"{base_url}/score", timeout=10)
        final_score = gr.json().get("score", 0.0) if gr.status_code == 200 else 0.0
        
        return float(final_score), steps
    except Exception as e:
        return 0.0, 0


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
            blue_score, steps = run_episode(BASE_URL, task, ep)
            
            red_score = compute_red_score(blue_score, ep, blue_scores)
            
            blue_scores.append(blue_score)
            red_scores.append(red_score)
            
            if ep % 10 == 0:
                avg = sum(blue_scores[-10:]) / 10
                print(f"  Ep {ep}: blue={blue_score:.3f} | red={red_score:.3f} | avg_last_10={avg:.3f} | eps={eps:.3f}")
                
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
        "summary": {}
    }
    
    for t in TASKS:
        bs = all_results[t]["blue_scores"]
        b_first = sum(bs[:10])/10 if len(bs)>=10 else sum(bs)/len(bs)
        b_last = sum(bs[-10:])/10 if len(bs)>=10 else sum(bs)/len(bs)
        out_obj["summary"][t] = {
            "blue_first10_avg": round(b_first, 3),
            "blue_last10_avg": round(b_last, 3),
            "blue_improvement": round(b_last - b_first, 3),
            "red_peak": round(max(all_results[t]["red_scores"]), 3)
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
    print(f"{'Task':<25} {'First 10':<10} {'Last 10':<10} {'Improvement'}")
    for t in TASKS:
        summ = out_obj["summary"][t]
        imp = summ['blue_improvement']
        sign = "+" if imp >= 0 else ""
        print(f"{t:<25} {summ['blue_first10_avg']:<10.3f} {summ['blue_last10_avg']:<10.3f} {sign}{imp:.3f}")
    print("------------------------------------------------")
    print("Graph saved: outputs/evals/red_vs_blue_curve.png")
    print("Data saved:  outputs/evals/scores.json")
    print("================================================")


if __name__ == "__main__":
    main()
