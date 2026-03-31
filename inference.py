"""
SOC Simulator — Baseline Inference Script
==========================================
Runs an LLM-powered SOC analyst agent against all three tasks and
outputs deterministic, reproducible scores.

Environment Variables (per submission checklist)
-------------------------------------------------
  API_BASE_URL  — Base URL of the OpenAI-compatible LLM API endpoint
                  e.g. "https://api-inference.huggingface.co/v1"
                       "https://api.openai.com/v1"
                       "http://localhost:11434/v1"   (Ollama)
  MODEL_NAME    — Model identifier to use for inference
                  e.g. "meta-llama/Llama-3.3-70B-Instruct"
                       "gpt-4o-mini"
  HF_TOKEN      — Your Hugging Face / API key (used as Authorization bearer)

Usage
-----
  # With HuggingFace Inference API
  set API_BASE_URL=https://api-inference.huggingface.co/v1
  set MODEL_NAME=meta-llama/Llama-3.3-70B-Instruct
  set HF_TOKEN=hf_...
  python inference.py

  # With OpenAI
  set API_BASE_URL=https://api.openai.com/v1
  set MODEL_NAME=gpt-4o-mini
  set HF_TOKEN=sk-...
  python inference.py

  # No API key — heuristic agent runs automatically
  python inference.py

Runtime: < 5 minutes typical  |  Memory: < 1 GB  |  CPU: 2 vCPU compatible
"""

from __future__ import annotations

import json
import os
import sys

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# ── Env var config (per submission checklist) ──────────────────────────────
# API_BASE_URL = LLM API endpoint (e.g. https://router.huggingface.co/v1)
# MODEL_NAME   = LLM model identifier
# HF_TOKEN     = Your HuggingFace / API key
API_BASE_URL: str = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME: str = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")
# Mirror the sample script: try HF_TOKEN first, then API_KEY as fallback
API_KEY: Optional[str] = os.getenv("HF_TOKEN") or os.getenv("API_KEY")

# ── Environment runs embedded — no external server needed ──────────────────
# Add project root to path so imports resolve correctly
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from env.soc_environment import SOCEnvironment          # noqa: E402
from models import ActionType, SOCAction, SOCObservation  # noqa: E402

# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

TASKS = [
    "easy_phishing_login",
    "medium_brute_force_geo",
    "hard_apt_multistage",
]

TASK_MAX_STEPS = {
    "easy_phishing_login": 5,
    "medium_brute_force_geo": 8,
    "hard_apt_multistage": 15,
}

# ---------------------------------------------------------------------------
# OpenAI Client (uses API_BASE_URL + HF_TOKEN per checklist)
# ---------------------------------------------------------------------------

def _build_llm_client():
    """
    Build an OpenAI-compatible client — matches the official sample script pattern:
      client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("openai package not installed. Run: pip install openai")
        sys.exit(1)

    api_key = API_KEY or "EMPTY"    # "EMPTY" works for local/unauthenticated servers
    return OpenAI(base_url=API_BASE_URL, api_key=api_key)


def call_llm(client, messages: List[dict]) -> str:
    """
    Call the LLM via the OpenAI client.
    Uses API_BASE_URL as the endpoint and HF_TOKEN as the bearer key.
    """
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0.0,     # Deterministic output
        max_tokens=256,
    )
    return response.choices[0].message.content.strip()


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

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

    # Active Alerts (most important — show first)
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


# ---------------------------------------------------------------------------
# Action parsing
# ---------------------------------------------------------------------------

def parse_action(raw: str, step_num: int) -> SOCAction:
    """Parse LLM JSON output into a SOCAction, with fallback to ignore."""
    # Strip markdown code fences that some models add
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
    except (json.JSONDecodeError, ValueError, KeyError) as exc:
        print(f"    ⚠ Parse error on step {step_num}: {exc} — defaulting to ignore")
        return SOCAction(action_type=ActionType.IGNORE, reason="llm_parse_error")


# ---------------------------------------------------------------------------
# Heuristic fallback agent (no LLM needed)
# ---------------------------------------------------------------------------

def heuristic_action(obs: SOCObservation) -> SOCAction:
    """
    Rule-based SOC analyst — used when no API key is configured.
    Provides a reasonable baseline and ensures inference.py always produces scores.
    """
    ss = obs.system_state
    blocked = set(ss.blocked_ips)
    flagged = set(ss.flagged_users)
    isolated = set(ss.isolated_hosts)

    # Priority ordering: work through alerts highest severity first
    sorted_alerts = sorted(
        obs.active_alerts,
        key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.threat_level, 4),
    )

    for _alert in sorted_alerts:
        # Inspect events correlated with this alert
        for ev in obs.recent_events:
            ip = ev.source_ip
            country = ev.country or "US"
            etype = ev.event_type.value if hasattr(ev.event_type, "value") else str(ev.event_type)
            user = ev.user_id
            host = ev.host_id

            # Block malicious external IPs
            if ip and country not in ("US",) and ip not in blocked:
                if etype in (
                    "phishing_email", "port_scan", "data_exfiltration",
                    "malware_execution", "network_scan",
                ):
                    return SOCAction(
                        action_type=ActionType.BLOCK_IP,
                        target=ip,
                        reason=f"Malicious {etype} from {country}",
                    )

            # Flag compromised accounts (geo-anomaly login)
            if user and user not in flagged and etype == "login_success":
                if country not in ("US",):
                    return SOCAction(
                        action_type=ActionType.FLAG_USER,
                        target=user,
                        reason=f"Geo-anomaly login from {country}",
                    )

            # Isolate compromised hosts
            if host and host not in isolated:
                if etype in ("malware_execution", "lateral_movement", "data_exfiltration"):
                    return SOCAction(
                        action_type=ActionType.ISOLATE_HOST,
                        target=host,
                        reason=f"Compromised host — {etype}",
                    )

        # Escalate critical alerts that haven't been resolved by specific actions
        if _alert.threat_level in ("critical", "high"):
            return SOCAction(
                action_type=ActionType.ESCALATE_ALERT,
                reason=f"Unresolved {_alert.threat_level} alert: {_alert.title}",
            )

    return SOCAction(action_type=ActionType.IGNORE, reason="No active threat detected")


# ---------------------------------------------------------------------------
# Single task runner
# ---------------------------------------------------------------------------

def run_task(
    env: SOCEnvironment,
    task_id: str,
    llm_client=None,
) -> dict:
    """
    Run one complete episode.

    Returns
    -------
    dict with: task_id, steps, score, explanation, duration_s
    """
    start_time = time.time()
    max_steps = TASK_MAX_STEPS.get(task_id, 10)
    use_llm = llm_client is not None

    print(f"\n{'═' * 62}")
    print(f"  TASK : {task_id}")
    print(f"  Mode : {'LLM (' + MODEL_NAME + ')' if use_llm else 'Heuristic baseline'}")
    print(f"{'═' * 62}")

    # ── Reset ────────────────────────────────────────────────────────────
    obs = env.reset(task_id=task_id)
    print(f"  Episode: {env.state.episode_id}")
    print(f"  Alerts : {len(obs.active_alerts)} | Events: {len(obs.recent_events)}")

    conversation = [{"role": "system", "content": SYSTEM_PROMPT}]
    step_num = 0

    # ── Agent loop ────────────────────────────────────────────────────────
    while not obs.done and step_num < max_steps:
        step_num += 1

        if use_llm:
            user_prompt = build_observation_prompt(obs, step_num)
            conversation.append({"role": "user", "content": user_prompt})
            try:
                raw_response = call_llm(llm_client, conversation)
                action = parse_action(raw_response, step_num)
                conversation.append({"role": "assistant", "content": raw_response})
            except Exception as exc:
                print(f"    ⚠ LLM call failed: {exc} — using heuristic fallback")
                action = heuristic_action(obs)
        else:
            action = heuristic_action(obs)

        target_display = action.target or ""
        print(
            f"\n  Step {step_num:>2}: {action.action_type:<18} "
            f"target={target_display:<22} reason={action.reason[:50] if action.reason else ''}"
        )

        obs = env.step(action)
        print(
            f"           reward={obs.reward:+.3f}  "
            f"done={obs.done}  "
            f"risk={obs.system_state.risk_score:.0%}  "
            f"FP={obs.metadata.get('false_positives', 0)}"
        )

    # ── Score ─────────────────────────────────────────────────────────────
    final_score = env.get_final_score()
    explanation = env.get_score_explanation()
    duration = round(time.time() - start_time, 2)

    assert 0.0 <= final_score <= 1.0, f"Score out of range: {final_score}"

    bar = "█" * int(final_score * 20) + "░" * (20 - int(final_score * 20))
    print(f"\n  Score : [{bar}] {final_score:.4f} ({final_score:.1%})")
    print(f"  Steps : {step_num}  |  Duration: {duration}s")

    return {
        "task_id": task_id,
        "steps": step_num,
        "score": round(final_score, 4),
        "explanation": explanation,
        "duration_s": duration,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Entry point — runs all 3 tasks and outputs scores.
    Exit code: 0 on success, 1 on fatal error.
    """
    print("🛡  SOC SIMULATOR — BASELINE INFERENCE")
    print(f"   Time       : {datetime.utcnow().isoformat()}Z")
    print(f"   API_BASE_URL: {API_BASE_URL}")
    print(f"   MODEL_NAME  : {MODEL_NAME}")
    print(f"   HF_TOKEN    : {'set (' + API_KEY[:8] + '...)' if API_KEY else 'NOT SET'}")

    # ── Initialise LLM client ────────────────────────────────────────────
    llm_client = None
    if API_KEY:
        try:
            llm_client = _build_llm_client()
            # Quick connectivity test with a minimal call
            test = llm_client.chat.completions.create(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": "Reply with the word OK only."}],
                max_tokens=5,
            )
            print(f"\n   LLM ping   : ✅  response='{test.choices[0].message.content.strip()}'")
        except Exception as exc:
            print(f"\n   ⚠ LLM unavailable ({exc}) — falling back to heuristic agent.")
            llm_client = None
    else:
        print("\n   ⚠ HF_TOKEN not set — using heuristic baseline agent.")
        print("     Set API_BASE_URL, MODEL_NAME, HF_TOKEN to enable LLM mode.")

    # ── Run all tasks ────────────────────────────────────────────────────
    env = SOCEnvironment()
    results = []

    for task_id in TASKS:
        try:
            result = run_task(env, task_id, llm_client=llm_client)
            results.append(result)
        except Exception as exc:
            import traceback
            print(f"\n  ❌ Task {task_id} failed: {exc}")
            traceback.print_exc()
            results.append({
                "task_id": task_id,
                "steps": 0,
                "score": 0.0,
                "explanation": {},
                "error": str(exc),
            })

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'═' * 62}")
    print("  FINAL RESULTS SUMMARY")
    print(f"{'═' * 62}")

    total_score = 0.0
    all_valid = True
    for r in results:
        score = r.get("score", 0.0)
        total_score += score
        bar = "█" * int(score * 20) + "░" * (20 - int(score * 20))
        status = "✅" if 0.0 <= score <= 1.0 else "❌"
        print(f"  {status} {r['task_id']:<32} [{bar}] {score:.1%}")
        if not (0.0 <= score <= 1.0):
            all_valid = False

    avg = total_score / len(results) if results else 0.0
    total_time = sum(r.get("duration_s", 0) for r in results)

    print(f"\n  Average Score : {avg:.4f} ({avg:.1%})")
    print(f"  Total Time    : {total_time:.1f}s")
    print(f"  All scores in [0,1]: {'✅ YES' if all_valid else '❌ NO'}")
    print(f"{'═' * 62}\n")

    # ── Write results JSON ────────────────────────────────────────────────
    output_dir = os.path.join(ROOT, "outputs")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "inference_results.json")

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "model": MODEL_NAME,
        "api_base_url": API_BASE_URL,
        "llm_enabled": llm_client is not None,
        "average_score": round(avg, 4),
        "total_duration_s": round(total_time, 2),
        "results": results,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"  Results saved → {output_path}")

    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())
