"""
SOC Simulator — Inference Script
===================================
MANDATORY (Submission Checklist)
- API_BASE_URL: The API endpoint for the LLM.
- MODEL_NAME:   The model identifier to use for inference.
- HF_TOKEN:     Your Hugging Face / API key.

STDOUT FORMAT
- [START] task=<task_name> env=soc_simulator model=<model_name>
- [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
- [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

try:
    from openai import OpenAI
except ImportError:
    print("openai package not installed. Run: pip install openai")
    sys.exit(1)

# Add project root to path
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from env.soc_environment import SOCEnvironment
from models import ActionType, SOCAction, SOCObservation

# --- Environment Configuration ---
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")

BENCHMARK = "soc_simulator"
TASKS = ["easy_phishing_login", "medium_brute_force_geo", "hard_apt_multistage"]
SUCCESS_SCORE_THRESHOLD = 0.1

# --- Prompts ---
SYSTEM_PROMPT = """You are an expert AI Security Operations Center (SOC) analyst.
You analyse security logs and SIEM alerts, then decide on the best response action.

You MUST respond with ONLY a valid JSON object — no markdown, no code fences, no explanation.

Available actions:
  {"action_type": "block_ip",       "target": "<IP address>",  "reason": "..."}
  {"action_type": "flag_user",      "target": "<username>",    "reason": "..."}
  {"action_type": "isolate_host",   "target": "<hostname>",    "reason": "..."}
  {"action_type": "escalate_alert", "target": null,            "reason": "..."}
  {"action_type": "ignore",         "target": null,            "reason": "..."}

Decision rules:
1. Phishing emails from foreign IPs                  → block_ip (source IP)
2. Successful login after phishing / MFA bypass      → flag_user (compromised account)
3. Brute-force attacks (many failures then success)  → block_ip (all attacking IPs)
4. Geo-anomaly login (impossible travel)             → flag_user + isolate_host
5. Web shells / reverse shells detected              → isolate_host (affected server)
6. Lateral movement via stolen service accounts      → isolate_host + flag_user
7. Large data exfiltration / C2 beaconing            → escalate_alert + block_ip (C2)
8. Multi-stage attacks: respond to stages in order   → recon→access→lateral→exfil

Only use "ignore" when all events are clearly benign.
Never block Google/Cloudflare DNS IPs (8.8.8.8, 1.1.1.1) or internal RFC1918 ranges."""

def build_observation_prompt(obs: SOCObservation, step_num: int) -> str:
    """Convert a SOCObservation into a textual dashboard for the LLM."""
    lines = [
        f"=== SOC ANALYST DASHBOARD — Step {step_num} ===",
        f"Task: {obs.task_id}  |  Timestamp: {obs.timestamp}",
        "",
    ]

    # Active Alerts
    alerts = obs.active_alerts
    if alerts:
        lines.append("━━━ ACTIVE SIEM ALERTS ━━━")
        for alert in sorted(alerts, key=lambda a: {"critical": 0, "high": 1, "medium": 2}.get(a.threat_level, 3)):
            lines.append(f"[{alert.threat_level.upper()}] {alert.title}")
            lines.append(f"  {alert.description[:300]}")
            lines.append(f"  Anomaly Score: {alert.anomaly_score:.2f}")
            if alert.mitre_technique:
                lines.append(f"  MITRE: {alert.mitre_tactic} / {alert.mitre_technique}")
            lines.append("")

    # Recent log events (last 6)
    events = obs.recent_events[-6:]
    if events:
        lines.append("━━━ RECENT LOG EVENTS ━━━")
        for ev in events:
            raw = ev.raw_log or (
                f"[{ev.event_type.upper()}] "
                f"src={ev.source_ip} user={ev.user_id} "
                f"host={ev.host_id} country={ev.country}"
            )
            lines.append(f"  {raw}")
        lines.append("")

    # System state
    ss = obs.system_state
    lines.append("━━━ SYSTEM STATE ━━━")
    lines.append(f"  Risk Score       : {ss.risk_score:.0%}")
    lines.append(f"  Anomaly Score    : {obs.network_anomaly_score:.2f}")
    lines.append(f"  Blocked IPs      : {ss.blocked_ips or 'none'}")
    lines.append(f"  Flagged Users    : {ss.flagged_users or 'none'}")
    lines.append(f"  Isolated Hosts   : {ss.isolated_hosts or 'none'}")
    lines.append(f"  Open Incidents   : {ss.open_incidents}")
    if obs.attack_stage:
        lines.append(f"  Attack Stage     : {obs.attack_stage.upper()}")
    if obs.hint:
        lines.append(f"  HINT             : {obs.hint}")
    lines.append("")
    lines.append("Based on the above, what is your next action?")
    lines.append("Respond with ONLY a valid JSON action object.")
    return "\n".join(lines)

# --- Logging Utils ---
def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)

# --- LLM Integration ---
def parse_action(raw: str) -> SOCAction:
    """Parse LLM JSON output into a SOCAction, with fallback to ignore."""
    text = raw.strip()
    for fence in ("```json", "```JSON", "```"):
        if text.startswith(fence):
            text = text[len(fence):]
    text = text.rstrip("```").strip()

    try:
        data = json.loads(text)
        atype = ActionType(data.get("action_type", "ignore"))
        return SOCAction(
            action_type=atype,
            target=data.get("target"),
            reason=data.get("reason", ""),
            confidence=float(data.get("confidence", 1.0)),
        )
    except Exception:
        return SOCAction(action_type=ActionType.IGNORE, reason="llm_parse_error")

def get_model_message(client: OpenAI, conversation: List[dict]) -> str:
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=conversation,
            temperature=0.0,
            max_tokens=256,
            stream=False,
        )
        return (completion.choices[0].message.content or "").strip()
    except Exception as exc:
        # If API key is missing or call fails, return a default ignore action
        return '{"action_type": "ignore", "reason": "api_call_failed"}'

# --- Task Execution ---
async def run_task_episode(client: OpenAI, env: SOCEnvironment, task_id: str) -> bool:
    log_start(task=task_id, env=BENCHMARK, model=MODEL_NAME)
    
    rewards = []
    steps_taken = 0
    score = 0.0
    success = False
    
    try:
        obs = env.reset(task_id=task_id)
        conversation = [{"role": "system", "content": SYSTEM_PROMPT}]
        
        # Max steps per task
        max_steps = 15 if "hard" in task_id else (8 if "medium" in task_id else 5)
        
        for step in range(1, max_steps + 1):
            if obs.done:
                break
                
            prompt = build_observation_prompt(obs, step)
            conversation.append({"role": "user", "content": prompt})
            
            raw_response = get_model_message(client, conversation)
            action = parse_action(raw_response)
            conversation.append({"role": "assistant", "content": raw_response})
            
            # Format action for logging
            action_desc = f"{action.action_type}:{action.target}" if action.target else f"{action.action_type}"
            
            obs = env.step(action)
            reward = obs.reward
            done = obs.done
            
            rewards.append(reward)
            steps_taken = step
            
            log_step(step=step, action=action_desc, reward=reward, done=done, error=None)
            
            if done:
                break
                
        score = env.get_final_score() # Already in [0, 1]
        success = score >= SUCCESS_SCORE_THRESHOLD
        
    except Exception as e:
        # Emit a step with error if something crashes mid-episode
        log_step(step=steps_taken+1, action="error", reward=0.0, done=True, error=str(e))
    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)
        
    return success

async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "EMPTY")
    env = SOCEnvironment()
    
    for task_id in TASKS:
        await run_task_episode(client, env, task_id)

if __name__ == "__main__":
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    asyncio.run(main())
