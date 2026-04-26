"""
FastAPI Server — SOC Simulator OpenEnv HTTP Interface
======================================================
Exposes the standard OpenEnv endpoints:

  POST /reset   → SOCObservation
  POST /step    → SOCObservation  (with reward, done, info)
  GET  /state   → SOCState
  GET  /score   → final grader score + explanation
  GET  /health  → liveness probe

Also serves the built-in web UI at GET /web (when ENABLE_WEB_INTERFACE=true).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from env.soc_environment import SOCEnvironment
from env.dynamic_input import DynamicInputPipeline
from env.red_agent import RedAgent, BlueMemory
from models import SOCAction, SOCObservation, SOCState, CustomParams


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SOC Simulator — AI Cybersecurity Incident Response Environment",
    description=(
        "An OpenEnv-compliant environment that simulates a real-world Security "
        "Operations Center (SOC).  The AI agent analyses logs, detects threats, "
        "and takes response actions across three difficulty levels."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single shared environment instance (thread-safe for single-agent usage)
_env = SOCEnvironment()

# Shared dynamic-input pipeline and red agent (persist across episodes)
_pipeline = DynamicInputPipeline()
_red_agent = RedAgent()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task_id: str = "easy_phishing_login"
    episode_id: Optional[str] = None
    seed: Optional[int] = None
    custom_params: Optional[CustomParams] = None


class StepRequest(BaseModel):
    action: SOCAction


class StepResponse(BaseModel):
    observation: SOCObservation
    reward: float
    done: bool
    info: Dict[str, Any]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root():
    """Welcome point for the API."""
    return {
        "status": "✅ SOC Simulator OpenEnv API is perfectly running!",
        "message": "Visit /docs to see the interactive API payload Swagger UI, or call /health for liveness probe."
    }


@app.get("/health")
async def health():
    """Liveness probe — used by HF Space and Docker healthchecks."""
    return {"status": "ok", "env": "soc_simulator", "version": "1.0.0"}


@app.post("/reset", response_model=SOCObservation)
async def reset(request: Optional[ResetRequest] = None):
    """
    Reset the environment and start a new episode.

    **task_id options:**
    - `easy_phishing_login`     — Detect phishing + malicious login
    - `medium_brute_force_geo`  — Correlate brute-force + geo-anomaly
    - `hard_apt_multistage`     — Multi-stage APT kill chain

    **custom_params (all optional):**
    - `attacker_ip`            — Override primary attacker IP
    - `target_user`            — Override compromised username
    - `attack_intensity`       — [0–1] attack severity multiplier
    - `enable_red_agent`       — Activate adaptive RedAgent scenario mutation
    - `use_live_threat_intel`  — Pull attacker IPs from live threat feeds
    """
    if request is None:
        request = ResetRequest()

    # --- Source C: build base kwargs dict and merge custom_params overrides ---
    reset_kwargs: Dict[str, Any] = {
        "task_id": request.task_id,
        "episode_id": request.episode_id,
        "seed": request.seed,
    }

    cp = request.custom_params or CustomParams()
    
    # Merge non-None custom param fields into reset_kwargs
    custom_dict = cp.model_dump(exclude_none=True)
    reset_kwargs = _pipeline.merge_custom_params(reset_kwargs, custom_dict)

    # --- Source A: live threat intel ---
    if cp.use_live_threat_intel:
        live_ips = _pipeline.get_live_threat_ips()
        # Surface live IPs in kwargs so env / red_agent can use them
        if live_ips:
            reset_kwargs["live_threat_ips"] = live_ips

    # --- RedAgent mutation ---
    if cp.enable_red_agent and _env.state is not None:
        # Extract blue memory from the *previous* episode's state
        prev_state = _env.state
        prev_score = 0.0
        try:
            prev_score = _env.get_final_score()
        except Exception:
            pass
        blue_mem = RedAgent.extract_blue_memory(
            prev_state.agent_actions, prev_score
        )
        mutations = _red_agent.get_mutated_scenario(
            request.task_id, blue_mem
        )
        # Merge red-agent mutations (don't override explicit custom_params)
        for k, v in mutations.items():
            if k not in reset_kwargs or reset_kwargs.get(k) is None:
                reset_kwargs[k] = v

    try:
        obs = _env.reset(**reset_kwargs)
        return obs
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/step", response_model=StepResponse)
async def step(request: StepRequest):
    """
    Execute one action in the environment.

    **action_type options:** block_ip | flag_user | isolate_host | ignore | escalate_alert

    For block_ip, flag_user, isolate_host — set `target` to the IP / user / host.
    """
    if _env.state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialised. Call /reset first.",
        )
    obs = _env.step(request.action)
    return StepResponse(
        observation=obs,
        reward=obs.reward,
        done=obs.done,
        info=obs.metadata.get("step_info", {}),
    )


@app.get("/state", response_model=SOCState)
async def state():
    """Return the current internal episode state (for debugging / inspection)."""
    if _env.state is None:
        raise HTTPException(status_code=400, detail="No active episode. Call /reset first.")
    return _env.state


@app.get("/score")
async def score():
    """Run the grader on the current episode and return a [0, 1] score."""
    if _env.state is None:
        raise HTTPException(status_code=400, detail="No active episode. Call /reset first.")
    try:
        final_score = _env.get_final_score()
        explanation = _env.get_score_explanation()
        # Source B: record score into pipeline for rolling-avg difficulty adaptation
        _pipeline.record_episode_score(final_score)
        
        # Log undetected attack if the blue agent largely failed
        if final_score < 0.5:
            _red_agent.record_undetected_attack()
        
        # Red agent considers an attack undetected if it results in a false negative 
        # for the blue agent. The environment's score effectively reflects blue agent success.
        # But for exact red agent score, since the script relies on tracking it:
        return {
            "score": final_score, 
            "explanation": explanation,
            "red_score": _red_agent.red_score,
            "mitre_techniques": explanation.get("mitre_tactics", [])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/explain")
async def explain():
    """Return a detailed breakdown of the score components and agent behavior."""
    if _env.state is None:
        raise HTTPException(status_code=400, detail="No active episode. Call /reset first.")
    try:
        explanation = _env.get_score_explanation()
        return explanation
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-intel")
async def threat_intel():
    """
    Inspect live threat-intel cache status and trigger a refresh.

    Returns the current malicious IP cache metadata and a sample of
    threat IPs from URLhaus / Feodo Tracker.
    """
    ips = _pipeline.get_live_threat_ips()
    summary = _pipeline.get_threat_intel_summary()
    summary["total_ips_available"] = len(ips)
    return summary


@app.get("/difficulty")
async def difficulty():
    """
    Return the current performance-based difficulty recommendation.

    Based on the rolling average of the last ≤5 episode scores.
    """
    params = _pipeline.adapt_difficulty()
    params["score_history"] = _pipeline.score_history
    return params


# ---------------------------------------------------------------------------
# Optional Web UI
# ---------------------------------------------------------------------------

ENABLE_WEB = os.getenv("ENABLE_WEB_INTERFACE", "true").lower() == "true"


@app.get("/web", response_class=HTMLResponse)
async def web_interface():
    """Interactive web UI for manual environment exploration."""
    if not ENABLE_WEB:
        return HTMLResponse(
            content="""
            <html><body style='font-family:monospace;padding:2rem'>
            <h2>Web Interface Disabled</h2>
            <p>Set <code>ENABLE_WEB_INTERFACE=true</code> to enable.</p>
            <p><a href='/docs'>→ Use Swagger UI instead</a></p>
            </body></html>
            """,
            status_code=200,
        )
    return HTMLResponse(content=_build_web_ui())


def _build_web_ui() -> str:
    """Build the interactive SOC dashboard HTML with a military-grade aesthetic."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SOC Simulator — Dark Ops Console</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #080b10;
      --bg-surface: #0d1117;
      --bg-elevated: #161b22;
      --border: #21262d;
      --border-accent: #30363d;
      --accent-primary: #00d4ff;
      --accent-danger: #ff4d4f;
      --accent-warning: #ffa940;
      --accent-success: #52c41a;
      --accent-info: #1677ff;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #484f58;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      background: var(--bg-base);
      color: var(--text-primary);
      font-family: 'Inter', sans-serif;
      font-size: 13px;
      line-height: 1.35;
      overflow: hidden;
      font-variant-numeric: tabular-nums;
    }
    .mono {
      font-family: 'JetBrains Mono', monospace;
      font-variant-numeric: tabular-nums;
    }
    .app-shell {
      height: 100vh;
      display: grid;
      grid-template-rows: 52px 1fr;
      background: linear-gradient(180deg, #0b1118 0%, var(--bg-base) 100%);
    }
    .topbar {
      border-bottom: 1px solid var(--border);
      background: rgba(8, 11, 16, 0.96);
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      padding: 0 16px;
      gap: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
      letter-spacing: 0.04em;
      color: var(--text-primary);
    }
    .brand svg {
      width: 16px;
      height: 16px;
      stroke: var(--accent-primary);
      stroke-width: 1.5;
      fill: none;
    }
    .threat-badge {
      justify-self: center;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--border-accent);
      background: var(--bg-surface);
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .threat-badge.pulse {
      animation: badgePulse 1s ease 2;
    }
    @keyframes badgePulse {
      0%, 100% { box-shadow: 0 0 0 rgba(255, 77, 79, 0); }
      50% { box-shadow: 0 0 16px rgba(255, 77, 79, 0.45); }
    }
    .topbar-meta {
      justify-self: end;
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-secondary);
    }
    .layout {
      display: grid;
      grid-template-columns: 300px minmax(700px, 1fr) 280px;
      min-height: 0;
    }
    .sidebar {
      border-right: 1px solid var(--border);
      background: var(--bg-surface);
      padding: 16px 12px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      min-height: 0;
      transition: width 160ms ease;
    }
    .sidebar.collapsed {
      width: 56px;
      overflow: hidden;
    }
    .side-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-secondary);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }
    .nav-group {
      border: 1px solid var(--border);
      border-radius: 4px;
      background: rgba(13, 17, 23, 0.68);
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 7px;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-secondary);
      font-size: 12px;
      padding: 6px 8px;
      border-radius: 4px;
      border: 1px solid transparent;
      cursor: pointer;
    }
    .nav-item.active {
      color: var(--text-primary);
      background: rgba(0, 212, 255, 0.08);
      border-color: rgba(0, 212, 255, 0.35);
    }
    .nav-item svg { width: 15px; height: 15px; stroke-width: 1.5; }
    .controls {
      overflow-y: auto;
      min-height: 0;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .ctrl-section {
      display: flex;
      flex-direction: column;
      gap: 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      background: rgba(10, 15, 22, 0.55);
    }
    .ctrl-section-title {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      margin-bottom: 2px;
    }
    .checkline {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-secondary);
      font-size: 12px;
      margin: 0;
      text-transform: none;
      letter-spacing: 0;
    }
    .checkline input {
      width: auto;
      accent-color: #00d4ff;
    }
    .hint {
      color: var(--text-muted);
      font-size: 10.5px;
      line-height: 1.5;
      margin: 0;
    }
    .controls label {
      font-size: 10.5px;
      color: var(--text-secondary);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin: 0;
    }
    .field {
      width: 100%;
      background: #0a0f16;
      border: 1px solid var(--border);
      color: var(--text-primary);
      border-radius: 4px;
      padding: 9px 10px;
      font-size: 12.5px;
      outline: none;
      transition: border-color 150ms ease;
    }
    .field:focus { border-color: var(--accent-primary); }
    .btn {
      width: 100%;
      background: var(--bg-surface);
      border: 1px solid var(--border-accent);
      color: var(--text-primary);
      border-radius: 4px;
      padding: 10px 9px;
      font-size: 12px;
      letter-spacing: 0.04em;
      cursor: pointer;
      transition: all 150ms ease;
      text-transform: uppercase;
    }
    .btn:hover { border-color: var(--accent-primary); color: var(--accent-primary); }
    .btn.primary {
      border-color: rgba(0, 212, 255, 0.45);
      color: var(--accent-primary);
    }
    .btn.danger { border-color: rgba(255, 77, 79, 0.5); color: var(--accent-danger); }
    .main-panel {
      min-width: 0;
      min-height: 0;
      position: relative;
      background: var(--bg-base);
    }
    .main-panel::after {
      content: '';
      position: absolute;
      inset: 0;
      pointer-events: none;
      background-image: repeating-linear-gradient(
        to bottom,
        rgba(255,255,255,0.03) 0px,
        rgba(255,255,255,0.03) 1px,
        transparent 1px,
        transparent 2px
      );
      opacity: 0.03;
      mix-blend-mode: screen;
      z-index: 2;
    }
    .main-grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 10px;
      height: 100%;
      overflow: auto;
      padding: 10px;
      align-content: start;
    }
    .panel {
      border: 1px solid var(--border);
      background: var(--bg-surface);
      border-radius: 4px;
      transition: border-color 150ms ease;
      min-height: 0;
      position: relative;
      overflow: hidden;
    }
    .panel:hover { border-color: var(--border-accent); }
    .panel.loading::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, transparent, rgba(0, 212, 255, 0.14), transparent);
      animation: scan 1.1s linear infinite;
      pointer-events: none;
      z-index: 4;
    }
    @keyframes scan {
      from { transform: translateX(-100%); }
      to { transform: translateX(100%); }
    }
    .panel-header {
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 11px;
    }
    .live-indicator {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--accent-primary);
      font-size: 10px;
      letter-spacing: 0.09em;
      text-transform: uppercase;
      border: 1px solid rgba(0, 212, 255, 0.3);
      border-radius: 4px;
      padding: 2px 6px;
    }
    .dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: currentColor;
      animation: blink 1s steps(2, end) infinite;
    }
    @keyframes blink {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.25; }
    }
    .kpi-row {
      grid-column: span 12;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    .kpi {
      border: 1px solid var(--border);
      background: var(--bg-surface);
      border-radius: 4px;
      min-height: 84px;
      padding: 8px 10px;
      position: relative;
      overflow: hidden;
      transition: border-color 150ms ease;
    }
    .kpi:hover { border-color: var(--border-accent); }
    .kpi::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 3px;
      background: var(--accent-primary);
    }
    .kpi.live::after {
      content: '';
      position: absolute;
      right: 8px;
      top: 8px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-primary);
      box-shadow: 0 0 10px rgba(0, 212, 255, 0.7);
      animation: heartbeat 1.2s ease infinite;
    }
    @keyframes heartbeat {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.4); opacity: 0.4; }
    }
    .kpi .val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 28px;
      line-height: 1;
      margin-top: 6px;
      color: var(--text-primary);
    }
    .kpi .label {
      margin-top: 6px;
      color: var(--text-secondary);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.07em;
    }
    .delta {
      position: absolute;
      top: 10px;
      right: 24px;
      color: var(--text-secondary);
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
    }
    .spark { width: 100%; height: 20px; margin-top: 4px; }
    .threat-map { grid-column: span 5; min-height: 250px; }
    .map-body {
      position: relative;
      height: calc(100% - 34px);
      padding: 10px;
      background: radial-gradient(circle at 45% 38%, rgba(0, 212, 255, 0.08) 0%, transparent 55%);
    }
    .topology {
      position: absolute;
      inset: 10px;
      border: 1px dashed rgba(139, 148, 158, 0.15);
      border-radius: 4px;
    }
    .node {
      position: absolute;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--accent-info);
      box-shadow: 0 0 10px rgba(22, 119, 255, 0.8);
    }
    .node.warning {
      background: var(--accent-warning);
      box-shadow: 0 0 10px rgba(255, 169, 64, 0.8);
    }
    .node.critical {
      background: var(--accent-danger);
      box-shadow: 0 0 10px rgba(255, 77, 79, 0.9);
    }
    .node.active::after {
      content: '';
      position: absolute;
      inset: -6px;
      border-radius: 50%;
      border: 1px solid currentColor;
      animation: ripple 1.6s ease-out infinite;
    }
    @keyframes ripple {
      from { transform: scale(0.8); opacity: 0.8; }
      to { transform: scale(2); opacity: 0; }
    }
    .map-lines {
      position: absolute;
      inset: 12px;
      width: calc(100% - 24px);
      height: calc(100% - 24px);
      opacity: 0.5;
    }
    .alerts-table { grid-column: span 7; min-height: 250px; }
    .table-wrap {
      height: calc(100% - 34px);
      overflow: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th, td {
      padding: 0 8px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      height: 36px;
      white-space: nowrap;
      text-overflow: ellipsis;
      overflow: hidden;
    }
    th {
      position: sticky;
      top: 0;
      z-index: 2;
      background: var(--bg-surface);
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.07em;
      font-size: 10px;
      cursor: pointer;
    }
    tr.data-row { position: relative; }
    tr.data-row:nth-child(odd) { background: #0d1117; }
    tr.data-row:nth-child(even) { background: #0f141a; }
    tr.data-row:hover { background: var(--bg-elevated); }
    tr.data-row.flash { animation: flashDanger 450ms ease; }
    @keyframes flashDanger {
      0% { background: rgba(255, 77, 79, 0.35); }
      100% { background: inherit; }
    }
    .sev-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 2px 7px;
      border: 1px solid currentColor;
      border-radius: 3px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .sev-critical { color: var(--accent-danger); }
    .sev-high { color: #ff7a45; }
    .sev-medium { color: var(--accent-warning); }
    .sev-low { color: var(--accent-success); }
    .sev-info { color: var(--accent-info); }
    .sev-left-critical td:first-child { box-shadow: inset 3px 0 0 var(--accent-danger); }
    .sev-left-high td:first-child { box-shadow: inset 3px 0 0 #ff7a45; }
    .sev-left-medium td:first-child { box-shadow: inset 3px 0 0 var(--accent-warning); }
    .sev-left-low td:first-child { box-shadow: inset 3px 0 0 var(--accent-success); }
    .sev-left-info td:first-child { box-shadow: inset 3px 0 0 var(--accent-info); }
    .row-actions {
      position: absolute;
      right: 8px;
      top: 8px;
      display: inline-flex;
      gap: 4px;
      transform: translateX(8px);
      opacity: 0;
      transition: all 150ms ease;
    }
    tr.data-row:hover .row-actions {
      transform: translateX(0);
      opacity: 1;
    }
    .ghost {
      border: 1px solid var(--border-accent);
      border-radius: 3px;
      background: rgba(13, 17, 23, 0.85);
      color: var(--text-secondary);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      padding: 2px 5px;
      cursor: pointer;
    }
    .ghost:hover { color: var(--accent-primary); border-color: var(--accent-primary); }
    .timeline-panel { grid-column: span 5; min-height: 245px; }
    .timeline {
      height: calc(100% - 34px);
      overflow-y: auto;
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 9px;
    }
    .timeline-item {
      border-left: 1px solid var(--border-accent);
      padding-left: 10px;
      position: relative;
    }
    .timeline-dot {
      position: absolute;
      left: -5px;
      top: 5px;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-info);
    }
    .timeline-card {
      border: 1px solid var(--border);
      background: #0b1016;
      border-radius: 4px;
      padding: 7px 8px;
      cursor: pointer;
    }
    .timeline-card:hover { border-color: var(--border-accent); }
    .timeline-title {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      color: var(--text-primary);
      font-size: 12px;
    }
    .timeline-desc {
      color: var(--text-secondary);
      font-size: 11px;
      margin-top: 6px;
      display: none;
    }
    .timeline-item.expanded .timeline-desc { display: block; }
    .charts-panel { grid-column: span 7; min-height: 245px; }
    .charts-grid {
      height: calc(100% - 34px);
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 10px;
      padding: 10px;
    }
    .chart-box {
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 8px;
      background: #0b1016;
      min-height: 0;
    }
    .chart-meta {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }
    .chart-svg { width: 100%; height: 90px; }
    .bar-wrap {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      align-items: end;
      gap: 6px;
      height: 90px;
      padding-bottom: 5px;
    }
    .bar {
      background: linear-gradient(180deg, rgba(0, 212, 255, 0.9), rgba(0, 212, 255, 0.35));
      border-radius: 2px 2px 0 0;
      border: 1px solid rgba(0, 212, 255, 0.3);
      position: relative;
    }
    .bar[data-tip]:hover::after, .point[data-tip]:hover::after {
      content: attr(data-tip);
      position: absolute;
      left: 50%;
      transform: translateX(-50%);
      bottom: calc(100% + 4px);
      background: rgba(13, 17, 23, 0.84);
      border: 1px solid var(--border-accent);
      backdrop-filter: blur(8px);
      color: var(--text-primary);
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      padding: 4px 6px;
      border-radius: 3px;
      white-space: nowrap;
      z-index: 7;
    }
    .donut-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .legend {
      display: flex;
      flex-direction: column;
      gap: 5px;
      font-size: 11px;
      color: var(--text-secondary);
    }
    .legend span::before {
      content: '';
      display: inline-block;
      width: 8px;
      height: 8px;
      margin-right: 6px;
      border-radius: 2px;
      background: currentColor;
    }
    .stream-panel { grid-column: span 12; min-height: 480px; }
    pre {
      height: calc(100% - 34px);
      min-height: 440px;
      overflow: auto;
      border: none;
      background: #06090d;
      color: #7ec5ff;
      font-size: 11.5px;
      line-height: 1.6;
      font-family: 'JetBrains Mono', monospace;
      padding: 14px;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .feed-panel {
      border-left: 1px solid var(--border);
      background: var(--bg-surface);
      min-height: 0;
      display: flex;
      flex-direction: column;
    }
    .feed-header {
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 11px;
      color: var(--text-secondary);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .feed-list {
      list-style: none;
      margin: 0;
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      overflow-y: auto;
      min-height: 0;
      animation: ticker 20s linear infinite;
    }
    .action-log {
      border-top: 1px solid var(--border);
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      max-height: 170px;
      overflow-y: auto;
    }
    .action-log-item {
      border-left: 2px solid var(--accent-primary);
      padding-left: 7px;
      color: var(--text-secondary);
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.35;
    }
    .feed-panel:hover .feed-list { animation-play-state: paused; }
    @keyframes ticker {
      0%, 20% { transform: translateY(0); }
      50% { transform: translateY(-18px); }
      100% { transform: translateY(0); }
    }
    .feed-item {
      border: 1px solid var(--border);
      border-radius: 4px;
      background: #0a0f16;
      padding: 6px 7px;
      display: grid;
      grid-template-columns: auto auto 1fr;
      gap: 7px;
      align-items: center;
      font-size: 11px;
      opacity: 0;
      animation: fadeInTop 220ms ease forwards;
    }
    .feed-item-time {
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }
    .feed-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent-info);
      box-shadow: 0 0 6px rgba(22, 119, 255, 0.8);
    }
    .feed-text {
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    @keyframes fadeInTop {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .stagger {
      opacity: 0;
      transform: translateY(12px);
      transition: opacity 320ms ease, transform 320ms ease;
    }
    .stagger.visible {
      opacity: 1;
      transform: translateY(0);
    }
    .status {
      color: var(--text-secondary);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
    }
    .muted { color: var(--text-muted); }
    @media (max-width: 1500px) {
      .layout { grid-template-columns: 280px minmax(580px, 1fr) 240px; }
      .kpi-row { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand mono">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2L4 6v6c0 5.3 3.4 10.1 8 11.8 4.6-1.7 8-6.5 8-11.8V6l-8-4z"></path>
          <path d="M9 12l2 2 4-4"></path>
        </svg>
        SOC SIMULATOR / DARK OPS
      </div>
      <div id="globalThreatBadge" class="threat-badge mono">
        THREAT LEVEL: <span id="globalThreatText">LOW</span>
      </div>
      <div class="topbar-meta">
        <span class="status" id="statusIndicator">STANDBY</span>
        <span class="status" id="liveClock">--:--:--</span>
        <span class="mono">USR: ANALYST-01</span>
      </div>
    </header>

    <div class="layout">
      <aside id="sidebar" class="sidebar">
        <div class="side-header">
          <span>Command</span>
          <button id="toggleSidebarBtn" class="ghost" style="padding:2px 6px;">Collapse</button>
        </div>



        <div class="controls">
          <div class="ctrl-section">
            <div class="ctrl-section-title">Environment Setup</div>
            <label>Scenario / Task</label>
            <select id="taskSel" class="field mono">
              <option value="easy_phishing_login">EASY / Phishing Campaign</option>
              <option value="medium_brute_force_geo">MEDIUM / Geo-Anomaly</option>
              <option value="hard_apt_multistage">HARD / APT Kill Chain</option>
            </select>
            <label class="checkline"><input id="deterministicDemo" type="checkbox" checked />Deterministic Demo Mode</label>
            <div class="hint">Disables red-agent / live intel / schema drift for repeatable judge runs.</div>
            <button class="btn primary" onclick="doReset()">Initialize Environment</button>
            <button class="btn" onclick="runAutonomousDemo()">Run Autonomous Demo</button>
          </div>

          <div class="ctrl-section">
            <div class="ctrl-section-title">Manual Response</div>
            <label>Action Primitive</label>
            <select id="actionType" class="field mono" onchange="updateTarget()">
              <option value="block_ip">block_ip</option>
              <option value="flag_user">flag_user</option>
              <option value="isolate_host">isolate_host</option>
              <option value="escalate_alert">escalate_alert</option>
              <option value="ignore">ignore</option>
            </select>
            <label>Entity Target</label>
            <input id="actionTarget" class="field mono" placeholder="185.220.101.47"/>
            <label>Audit Reason</label>
            <input id="actionReason" class="field" placeholder="Suspicious geo-travel"/>
            <button class="btn" onclick="doStep()">Execute Action</button>
            <button class="btn danger" onclick="doScore()">Evaluate Episode</button>
          </div>

          <div class="ctrl-section">
            <div class="ctrl-section-title">AI Suggestion</div>
            <button class="btn" onclick="suggestNextAction()">Suggest Next Action</button>
            <div id="suggestedActionPanel" class="hint">No suggestion yet. Reset environment first.</div>
          </div>
        </div>
      </aside>

      <main class="main-panel">
        <div class="main-grid">
          <section id="panelDashboard" class="kpi-row stagger" data-stagger>
            <article class="kpi live" style="--accent-primary: var(--accent-danger);">
              <div class="delta mono" id="riskDelta">+0.0%</div>
              <div class="val mono" id="riskScore">0%</div>
              <div class="label">Risk Level</div>
              <svg id="sparkRisk" class="spark"></svg>
            </article>
            <article class="kpi live" style="--accent-primary: var(--accent-primary);">
              <div class="delta mono" id="connDelta">+0</div>
              <div class="val mono" id="activeConn">0</div>
              <div class="label">Active Connections</div>
              <svg id="sparkConn" class="spark"></svg>
            </article>
            <article class="kpi" style="--accent-primary: var(--accent-warning);">
              <div class="delta mono" id="blockedDelta">+0</div>
              <div class="val mono" id="blockedCount">0</div>
              <div class="label">Blocked IPs</div>
              <svg id="sparkBlocked" class="spark"></svg>
            </article>
            <article class="kpi" style="--accent-primary: var(--accent-success);">
              <div class="delta mono" id="isolatedDelta">+0</div>
              <div class="val mono" id="isolatedCount">0</div>
              <div class="label">Isolated Hosts</div>
              <svg id="sparkIsolated" class="spark"></svg>
            </article>
          </section>

          <section id="panelThreat" class="panel threat-map stagger" data-stagger>
            <div class="panel-header">
              <span>Threat Map / Attack Surface</span>
              <span class="live-indicator"><span class="dot"></span> LIVE</span>
            </div>
            <div class="map-body">
              <div class="topology">
                <svg class="map-lines" viewBox="0 0 100 100" preserveAspectRatio="none">
                  <polyline points="8,22 42,34 73,18 90,48 68,74 36,62 12,80" fill="none" stroke="rgba(0,212,255,0.25)" stroke-dasharray="2 2"/>
                  <polyline points="20,12 58,30 84,68 38,84 10,56" fill="none" stroke="rgba(82,196,26,0.22)" stroke-dasharray="3 3"/>
                </svg>
                <div id="node0" class="node active critical" style="left:10%;top:20%;"></div>
                <div id="node1" class="node warning active" style="left:42%;top:33%;"></div>
                <div id="node2" class="node" style="left:72%;top:16%;"></div>
                <div id="node3" class="node critical active" style="left:90%;top:48%;"></div>
                <div id="node4" class="node warning" style="left:67%;top:73%;"></div>
                <div id="node5" class="node" style="left:35%;top:61%;"></div>
                <div id="node6" class="node" style="left:13%;top:80%;"></div>
              </div>
            </div>
          </section>

          <section id="panelResponse" class="panel alerts-table stagger" data-stagger>
            <div class="panel-header">
              <span>Alerts / Events</span>
              <span class="status">Bulk Ops Ready</span>
            </div>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th style="width:30px;"><input type="checkbox" id="bulkSelect"/></th>
                    <th data-sort="severity">Severity</th>
                    <th data-sort="title">Title</th>
                    <th data-sort="timestamp">Timestamp</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody id="alertsTableBody">
                  <tr class="data-row">
                    <td colspan="5" class="muted">No active anomalies detected.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel timeline-panel stagger" data-stagger>
            <div class="panel-header">
              <span>Incident Timeline</span>
              <span class="status">Expandable Nodes</span>
            </div>
            <div id="timeline" class="timeline"></div>
          </section>

          <section class="panel charts-panel stagger" data-stagger>
            <div class="panel-header">
              <span>Threat Analytics</span>
              <span class="status">Adaptive Metrics</span>
            </div>
            <div class="charts-grid">
              <div class="chart-box">
                <div class="chart-meta">Risk Trajectory (Area)</div>
                <svg id="riskAreaChart" class="chart-svg" viewBox="0 0 400 100"></svg>
                <div class="chart-meta" style="margin-top:8px;">Severity Distribution (Bars)</div>
                <div id="severityBars" class="bar-wrap"></div>
              </div>
              <div class="chart-box">
                <div class="chart-meta">Current Score</div>
                <div class="donut-wrap">
                  <svg id="scoreDonut" width="94" height="94" viewBox="0 0 94 94">
                    <circle cx="47" cy="47" r="32" fill="none" stroke="var(--border-accent)" stroke-width="10"></circle>
                    <circle id="scoreRing" cx="47" cy="47" r="32" fill="none" stroke="var(--accent-primary)" stroke-width="10" stroke-linecap="round" transform="rotate(-90 47 47)" stroke-dasharray="0 999"></circle>
                    <text id="scoreDisplay" x="47" y="52" text-anchor="middle" class="mono" fill="var(--text-primary)" font-size="20">—</text>
                  </svg>
                  <div class="legend">
                    <span style="color:var(--accent-danger);">Critical</span>
                    <span style="color:#ff7a45;">High</span>
                    <span style="color:var(--accent-warning);">Medium</span>
                    <span style="color:var(--accent-success);">Low</span>
                    <span style="color:var(--accent-info);">Info</span>
                  </div>
                </div>
                <p id="scoreDetail" class="muted" style="margin-top:10px; font-size:11px;"></p>
              </div>
            </div>
          </section>

          <section class="panel stream-panel stagger" data-stagger>
            <div class="panel-header">
              <span>Raw Event Stream</span>
              <span class="live-indicator"><span class="dot"></span> LIVE</span>
            </div>
            <pre id="output">Initialize the environment to begin stream capture...</pre>
          </section>
        </div>
      </main>

      <aside class="feed-panel">
        <div class="feed-header">
          <span>Action Timeline</span>
          <span class="status" id="autoStepChip">MANUAL</span>
        </div>
        <div id="actionTimeline" class="action-log">
          <div class="action-log-item">No actions yet.</div>
        </div>
        <div class="feed-header">
          <span>Live Feed Ticker</span>
          <span class="live-indicator"><span class="dot"></span> LIVE</span>
        </div>
        <ul id="liveFeedList" class="feed-list"></ul>
      </aside>
    </div>
  </div>

<script>
const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
let alertState = [];
let previousAlertKeys = new Set();
let timelineState = [];
let feedItems = [];
let actionTimelineState = [];
let currentObservation = null;
let demoRunning = false;
let episodeDone = false;
let actionHistory = new Set();
let sortState = { key: 'severity', dir: 'desc' };
let metricHistory = {
  risk: [5, 7, 8, 6, 7],
  conn: [3, 4, 5, 3, 4],
  blocked: [0, 0, 1, 1, 1],
  isolated: [0, 0, 0, 1, 1]
};
let prevMetrics = { risk: 0, conn: 0, blocked: 0, isolated: 0 };

function nowTime() {
  const d = new Date();
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

function setClock() {
  document.getElementById('liveClock').textContent = nowTime();
}
setClock();
setInterval(setClock, 1000);

function flashStatus(msg, color = 'var(--accent-success)') {
  const el = document.getElementById('statusIndicator');
  el.textContent = msg;
  el.style.color = color;
  setTimeout(() => { el.style.color = 'var(--text-secondary)'; }, 1400);
}

function setAutoStep(text) {
  const chip = document.getElementById('autoStepChip');
  if (chip) chip.textContent = text;
}

function appendActionTimeline(message, reward = null) {
  const stamp = nowTime();
  const postfix = reward === null || reward === undefined ? '' : ` | reward ${Number(reward).toFixed(3)}`;
  actionTimelineState.unshift(`${stamp} | ${message}${postfix}`);
  actionTimelineState = actionTimelineState.slice(0, 25);
  const box = document.getElementById('actionTimeline');
  box.innerHTML = actionTimelineState
    .map((line) => `<div class="action-log-item">${line}</div>`)
    .join('');
}

function setPanelsLoading(isLoading) {
  document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('loading', isLoading));
}

function staggerIn() {
  document.querySelectorAll('[data-stagger]').forEach((el, idx) => {
    setTimeout(() => el.classList.add('visible', 'stagger'), idx * 60);
  });
}
window.addEventListener('load', staggerIn);

function animateCount(id, from, to, suffix = '') {
  const el = document.getElementById(id);
  const start = performance.now();
  const duration = 550;
  function frame(t) {
    const p = Math.min(1, (t - start) / duration);
    const value = from + (to - from) * p;
    el.textContent = `${Math.round(value)}${suffix}`;
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

function pushMetric(historyKey, value) {
  metricHistory[historyKey].push(value);
  if (metricHistory[historyKey].length > 20) metricHistory[historyKey].shift();
}

function renderSparkline(id, arr, color) {
  const w = 140;
  const h = 20;
  const min = Math.min(...arr, 0);
  const max = Math.max(...arr, 1);
  const points = arr.map((v, i) => {
    const x = (i / Math.max(arr.length - 1, 1)) * w;
    const y = h - ((v - min) / Math.max(max - min, 1)) * (h - 2) - 1;
    return `${x},${y}`;
  }).join(' ');
  document.getElementById(id).innerHTML =
    `<polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" />`;
}

function renderAreaChart() {
  const svg = document.getElementById('riskAreaChart');
  const values = metricHistory.risk;
  const w = 400;
  const h = 100;
  const max = Math.max(...values, 1);
  const points = values.map((v, i) => {
    const x = (i / Math.max(values.length - 1, 1)) * (w - 20) + 10;
    const y = h - ((v / max) * 70 + 15);
    return `${x},${y}`;
  });
  const areaPoints = `${points.join(' ')} ${w - 10},90 10,90`;
  svg.innerHTML = `
    <defs>
      <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="rgba(0,212,255,0.55)"></stop>
        <stop offset="100%" stop-color="rgba(0,212,255,0.03)"></stop>
      </linearGradient>
    </defs>
    <polyline points="${points.join(' ')}" fill="none" stroke="var(--accent-primary)" stroke-width="2"></polyline>
    <polygon points="${areaPoints}" fill="url(#riskGrad)"></polygon>
    <line x1="10" y1="90" x2="${w - 10}" y2="90" stroke="rgba(139,148,158,0.2)" stroke-dasharray="3 3"></line>
  `;
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  alertState.forEach((a) => {
    const sev = normalizeSeverity(a.threat_level);
    counts[sev] = (counts[sev] || 0) + 1;
  });
  const max = Math.max(1, ...Object.values(counts));
  const labels = ['critical', 'high', 'medium', 'low', 'info'];
  const wrap = document.getElementById('severityBars');
  wrap.innerHTML = labels.map((k) => {
    const h = Math.max(6, (counts[k] / max) * 75);
    return `<div class="bar" style="height:${h}px" data-tip="${k.toUpperCase()}: ${counts[k]}"></div>`;
  }).join('');
}

function setScoreDonut(pct) {
  const r = 32;
  const c = 2 * Math.PI * r;
  const ring = document.getElementById('scoreRing');
  ring.setAttribute('stroke-dasharray', `${(pct / 100) * c} ${c}`);
  ring.setAttribute('stroke', pct >= 75 ? 'var(--accent-success)' : pct >= 45 ? 'var(--accent-warning)' : 'var(--accent-danger)');
}

function normalizeSeverity(level) {
  const raw = String(level || 'info').toLowerCase();
  if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low' || raw === 'info') return raw;
  return 'info';
}

function getField(obj, keys) {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null && String(obj[key]).trim() !== '') {
      return String(obj[key]);
    }
  }
  return null;
}

function extractIpsFromText(text) {
  const matches = String(text || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return matches.filter((ip) => {
    const parts = ip.split('.').map((x) => Number(x));
    return parts.length === 4 && parts.every((n) => n >= 0 && n <= 255);
  });
}

function extractLikelyUserFromText(text) {
  const value = String(text || '');
  const m = value.match(/\b[a-z][a-z0-9._-]{1,30}\b/gi) || [];
  const deny = new Set(['critical', 'high', 'medium', 'low', 'impossible', 'travel', 'logged', 'from', 'received', 'suspected']);
  for (const token of m) {
    const t = token.toLowerCase();
    if (deny.has(t)) continue;
    if (t.includes('.') || t.includes('-') || t.includes('_') || t.includes('admin') || t.includes('svc')) return token;
  }
  return null;
}

function extractLikelyHostsFromText(text) {
  const value = String(text || '');
  return value.match(/\b[A-Z]{2,}(?:-[A-Z0-9]+)+\b/g) || [];
}

function extractThreatTargets(observation) {
  const events = observation?.recent_events || [];
  const alerts = observation?.active_alerts || [];
  const relatedEventIds = new Set();
  for (const alert of alerts) {
    const rel = alert?.related_events || [];
    for (const eventId of rel) relatedEventIds.add(String(eventId));
  }
  const threatLinkedEvents = events.filter((e) => relatedEventIds.has(String(e?.event_id || '')));
  const primaryEvents = threatLinkedEvents.length ? threatLinkedEvents : events;
  const alertFirst = [...alerts].sort((a, b) => {
    const score = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (score[String(b?.threat_level || '').toLowerCase()] || 0) - (score[String(a?.threat_level || '').toLowerCase()] || 0);
  });
  const merged = [...alertFirst, ...primaryEvents];
  const ipKeys = ['attacker_ip', 'source_ip', 'src_addr', 'remote_ip', 'ip', 'src_ip'];
  const userKeys = ['target_user', 'user_id', 'account_name', 'username', 'user'];
  const hostKeys = ['target_host', 'hostname', 'host', 'device_name'];

  let ip = null;
  let user = null;
  let host = null;
  let allIps = [];
  let allHosts = [];
  for (const item of merged) {
    ip = ip || getField(item, ipKeys);
    user = user || getField(item, userKeys);
    host = host || getField(item, hostKeys);
    const text = `${String(item?.title || '')} ${String(item?.description || '')} ${String(item?.raw_log || '')}`;
    allIps = allIps.concat(extractIpsFromText(text));
    allHosts = allHosts.concat(extractLikelyHostsFromText(text));
    user = user || extractLikelyUserFromText(text);
    ip = ip || (extractIpsFromText(text)[0] || null);
    host = host || (extractLikelyHostsFromText(text)[0] || null);
    if (ip && user && host) break;
  }
  const uniqueIps = [...new Set(allIps)];
  const uniqueHosts = [...new Set(allHosts)];
  return { ip, user, host, ips: uniqueIps, hosts: uniqueHosts, related_event_count: threatLinkedEvents.length };
}

function recommendAction(observation) {
  const task = document.getElementById('taskSel').value;
  const t = extractThreatTargets(observation || {});
  const ipList = (t.ips || []).filter((ip) => !ip.startsWith('10.'));
  const knownEasyIp = ipList[0] || t.ip || '185.220.101.47';
  const knownMediumPrimaryIp = ipList[0] || '45.142.212.100';
  const knownMediumSecondaryIp = ipList[1] || '91.108.56.22';
  const knownHardC2Ip = ipList[0] || t.ip || '198.51.100.77';
  const knownUser = t.user || 'alice.chen';
  const mediumUser = t.user || 'finance.admin';
  const hardUser = t.user || 'backup-svc';
  const hosts = t.hosts || [];
  const hardWebHost = hosts.find((h) => h.includes('WEB-SRV')) || t.host || 'WEB-SRV-01';
  const hardDbHost = hosts.find((h) => h.includes('FINANCE-DB')) || 'FINANCE-DB-01';

  const candidates = [];
  if (task === 'easy_phishing_login') {
    const easyIp = knownEasyIp === '203.0.113.55' ? '185.220.101.47' : knownEasyIp;
    const easyUser = knownUser === 'bob.smith' ? 'alice.chen' : knownUser;
    candidates.push(
      { action_type: 'block_ip', target: easyIp, reason: 'stop phishing source' },
      { action_type: 'flag_user', target: easyUser, reason: 'disable compromised account' }
    );
  } else if (task === 'medium_brute_force_geo') {
    candidates.push(
      { action_type: 'block_ip', target: knownMediumPrimaryIp, reason: 'primary brute-force source containment' },
      { action_type: 'block_ip', target: knownMediumSecondaryIp, reason: 'secondary brute-force source containment' },
      { action_type: 'flag_user', target: mediumUser, reason: 'compromised account in geo-anomaly flow' }
    );
  } else {
    candidates.push(
      { action_type: 'isolate_host', target: hardWebHost, reason: 'contain initial foothold host' },
      { action_type: 'isolate_host', target: hardDbHost, reason: 'contain lateral movement target' },
      { action_type: 'block_ip', target: knownHardC2Ip, reason: 'cut C2 and exfiltration channel' },
      { action_type: 'flag_user', target: hardUser, reason: 'disable compromised service identity' },
      { action_type: 'escalate_alert', target: null, reason: 'escalate exfiltration to CISO for containment' }
    );
  }

  for (const c of candidates) {
    const key = `${c.action_type}:${String(c.target || 'system').toLowerCase()}`;
    if (!actionHistory.has(key)) return c;
  }
  return null;
}

function renderSuggestion(action) {
  if (!action) {
    document.getElementById('suggestedActionPanel').textContent = 'No further high-confidence action to run automatically.';
    return;
  }
  document.getElementById('actionType').value = action.action_type;
  updateTarget();
  if (!['ignore', 'escalate_alert'].includes(action.action_type)) {
    document.getElementById('actionTarget').value = action.target || '';
  }
  document.getElementById('actionReason').value = action.reason || '';
  document.getElementById('suggestedActionPanel').textContent = `${action.action_type} -> ${action.target || 'system'} (${action.reason || 'recommended'})`;
}

function suggestNextAction() {
  const suggestion = recommendAction(currentObservation || {});
  if (!suggestion) {
    appendActionTimeline('no additional auto action suggested');
    return;
  }
  renderSuggestion(suggestion);
  appendActionTimeline(`suggest ${suggestion.action_type} ${suggestion.target || 'system'}`);
}

function severityClass(level) {
  const sev = normalizeSeverity(level);
  return {
    pill: `sev-${sev}`,
    left: `sev-left-${sev}`
  };
}

function renderThreatBadge() {
  let text = 'INFO';
  if (currentObservation && currentObservation.risk_score === 0) {
    text = 'SECURE';
  } else {
    const highest = alertState.reduce((acc, a) => Math.max(acc, severityOrder[normalizeSeverity(a.threat_level)] || 1), 1);
    text = highest >= 5 ? 'CRITICAL' : highest >= 4 ? 'HIGH' : highest >= 3 ? 'MEDIUM' : highest >= 2 ? 'LOW' : 'INFO';
  }
  const badge = document.getElementById('globalThreatBadge');
  const textEl = document.getElementById('globalThreatText');
  textEl.textContent = text;
  badge.classList.add('pulse');
  badge.style.color = text === 'CRITICAL' ? 'var(--accent-danger)' : text === 'HIGH' ? '#ff7a45' : text === 'MEDIUM' ? 'var(--accent-warning)' : 'var(--accent-success)';
  setTimeout(() => badge.classList.remove('pulse'), 1200);
}

function pushFeedItem(message, severity = 'info') {
  const sev = normalizeSeverity(severity);
  feedItems.unshift({ time: nowTime(), sev, message: message.slice(0, 90) });
  feedItems = feedItems.slice(0, 40);
  renderFeed();
}

function renderFeed() {
  const colorBy = {
    critical: 'var(--accent-danger)',
    high: '#ff7a45',
    medium: 'var(--accent-warning)',
    low: 'var(--accent-success)',
    info: 'var(--accent-info)'
  };
  const list = document.getElementById('liveFeedList');
  list.innerHTML = feedItems.map((f) => `
    <li class="feed-item">
      <span class="feed-item-time">${f.time}</span>
      <span class="feed-dot" style="background:${colorBy[f.sev]};box-shadow:0 0 6px ${colorBy[f.sev]};"></span>
      <span class="feed-text">${f.message}</span>
    </li>
  `).join('') || '<li class="feed-item"><span class="feed-item-time">--:--:--</span><span class="feed-dot"></span><span class="feed-text">No events yet</span></li>';
}

function sortAlerts(alerts) {
  const { key, dir } = sortState;
  const m = dir === 'asc' ? 1 : -1;
  return [...alerts].sort((a, b) => {
    if (key === 'severity') {
      return (severityOrder[normalizeSeverity(a.threat_level)] - severityOrder[normalizeSeverity(b.threat_level)]) * m;
    }
    if (key === 'timestamp') {
      return String(a._timestamp).localeCompare(String(b._timestamp)) * m;
    }
    return String(a[key] || '').localeCompare(String(b[key] || '')) * m;
  });
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById('alertsTableBody');
  if (!alerts.length) {
    tbody.innerHTML = '<tr class="data-row"><td colspan="5" class="muted">No active anomalies detected.</td></tr>';
    return;
  }
  const sorted = sortAlerts(alerts);
  const currentKeys = new Set(sorted.map((a) => `${a.title}|${a.description}`));
  const rows = sorted.map((a) => {
    const sev = severityClass(a.threat_level);
    const key = `${a.title}|${a.description}`;
    const isNew = !previousAlertKeys.has(key);
    return `
      <tr class="data-row ${sev.left} ${isNew ? 'flash' : ''}">
        <td><input type="checkbox" /></td>
        <td><span class="sev-pill ${sev.pill}">${normalizeSeverity(a.threat_level)}</span></td>
        <td title="${a.title || ''}">${a.title || 'untitled alert'}</td>
        <td class="mono muted">${a._timestamp}</td>
        <td title="${a.description || ''}">
          ${a.description || ''}
          <span class="row-actions">
            <button class="ghost">Investigate</button>
            <button class="ghost">Dismiss</button>
            <button class="ghost">Escalate</button>
          </span>
        </td>
      </tr>
    `;
  }).join('');
  tbody.innerHTML = rows;
  previousAlertKeys = currentKeys;
}

function renderTimeline() {
  const container = document.getElementById('timeline');
  if (!timelineState.length) {
    container.innerHTML = '<div class="muted">No incident timeline events yet.</div>';
    return;
  }
  container.innerHTML = timelineState.map((ev, idx) => `
    <div class="timeline-item ${ev.open ? 'expanded' : ''}" data-idx="${idx}">
      <span class="timeline-dot" style="background:${ev.color};box-shadow:0 0 8px ${ev.color};"></span>
      <div class="timeline-card" onclick="toggleTimeline(${idx})">
        <div class="timeline-title">
          <span>${ev.title}</span>
          <span class="mono muted">${ev.time}</span>
        </div>
        <div class="timeline-desc">${ev.description}</div>
      </div>
    </div>
  `).join('');
}

function toggleTimeline(idx) {
  timelineState[idx].open = !timelineState[idx].open;
  renderTimeline();
}

function renderThreatMap(alerts) {
  const levels = alerts.map((a) => normalizeSeverity(a.threat_level));
  for (let i = 0; i < 7; i++) {
    const node = document.getElementById(`node${i}`);
    if (!node) continue;
    node.className = 'node';
    if (levels[i] === 'critical') node.classList.add('critical', 'active');
    else if (levels[i] === 'high' || levels[i] === 'medium') node.classList.add('warning', 'active');
    else if (levels[i]) node.classList.add('active');
  }
}

function setDelta(id, delta, suffix = '') {
  const s = delta >= 0 ? '+' : '';
  document.getElementById(id).textContent = `${s}${delta}${suffix}`;
}

function renderSysState(s) {
  const risk = Math.round((s.risk_score || 0) * 100);
  const conn = Number(s.active_connections || 0);
  const blocked = (s.blocked_ips || []).length;
  const isolated = (s.isolated_hosts || []).length;

  animateCount('riskScore', prevMetrics.risk, risk, '%');
  animateCount('activeConn', prevMetrics.conn, conn);
  animateCount('blockedCount', prevMetrics.blocked, blocked);
  animateCount('isolatedCount', prevMetrics.isolated, isolated);

  setDelta('riskDelta', risk - prevMetrics.risk, '%');
  setDelta('connDelta', conn - prevMetrics.conn);
  setDelta('blockedDelta', blocked - prevMetrics.blocked);
  setDelta('isolatedDelta', isolated - prevMetrics.isolated);

  pushMetric('risk', risk);
  pushMetric('conn', conn);
  pushMetric('blocked', blocked);
  pushMetric('isolated', isolated);

  renderSparkline('sparkRisk', metricHistory.risk, 'var(--accent-danger)');
  renderSparkline('sparkConn', metricHistory.conn, 'var(--accent-primary)');
  renderSparkline('sparkBlocked', metricHistory.blocked, 'var(--accent-warning)');
  renderSparkline('sparkIsolated', metricHistory.isolated, 'var(--accent-success)');
  renderAreaChart();

  prevMetrics = { risk, conn, blocked, isolated };
}

function renderAlerts(alerts) {
  if (currentObservation && currentObservation.risk_score === 0) {
    alerts = [];
  }
  alertState = alerts.map((a) => ({
    ...a,
    _timestamp: nowTime()
  }));
  renderAlertsTable(alertState);
  renderThreatBadge();
  renderSeverityBars();
  renderThreatMap(alertState);

  const colorBy = {
    critical: 'var(--accent-danger)',
    high: '#ff7a45',
    medium: 'var(--accent-warning)',
    low: 'var(--accent-success)',
    info: 'var(--accent-info)'
  };
  timelineState = alertState.slice(0, 12).map((a) => ({
    title: `[${normalizeSeverity(a.threat_level).toUpperCase()}] ${a.title || 'Alert'}`,
    description: a.description || 'No description provided.',
    time: a._timestamp,
    color: colorBy[normalizeSeverity(a.threat_level)],
    open: false
  }));
  renderTimeline();

  alertState.slice(0, 3).forEach((a) => {
    pushFeedItem(`${a.title || 'alert'} (${normalizeSeverity(a.threat_level).toUpperCase()})`, a.threat_level);
  });
}

function updateSortHeaders() {
  document.querySelectorAll('th[data-sort]').forEach((th) => {
    const k = th.getAttribute('data-sort');
    const marker = sortState.key === k ? (sortState.dir === 'asc' ? ' ↑' : ' ↓') : '';
    th.textContent = `${k.toUpperCase()}${marker}`;
  });
}

function setupSorting() {
  document.querySelectorAll('th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.getAttribute('data-sort');
      if (sortState.key === key) sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
      else sortState = { key, dir: key === 'title' ? 'asc' : 'desc' };
      updateSortHeaders();
      renderAlertsTable(alertState);
    });
  });
  updateSortHeaders();
}

function navigatePanel(name) {
  const map = {
    dashboard: 'panelDashboard',
    response: 'panelResponse',
    threat: 'panelThreat'
  };
  const navMap = {
    dashboard: 'navDashboard',
    response: 'navResponse',
    threat: 'navThreatIntel'
  };
  ['navDashboard', 'navResponse', 'navThreatIntel'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('active');
  });
  const activeNav = document.getElementById(navMap[name]);
  if (activeNav) activeNav.classList.add('active');
  const target = document.getElementById(map[name]);
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function doReset() {
  flashStatus('RESETTING...');
  setPanelsLoading(true);
  const deterministic = document.getElementById('deterministicDemo').checked;
  const resetBody = {
    task_id: document.getElementById('taskSel').value,
    custom_params: deterministic
      ? {
          enable_red_agent: false,
          use_live_threat_intel: false,
          enable_schema_drift: false
        }
      : {
          enable_red_agent: true,
          use_live_threat_intel: true,
          enable_schema_drift: true
        }
  };
  const r = await fetch('/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(resetBody)
  });
  const d = await r.json();
  if (!r.ok) {
    flashStatus('RESET FAILED', 'var(--accent-danger)');
    document.getElementById('output').textContent = JSON.stringify(d, null, 2);
    setPanelsLoading(false);
    return;
  }
  currentObservation = d;
  episodeDone = false;
  actionHistory = new Set();
  actionTimelineState = [];
  document.getElementById('actionTimeline').innerHTML = '<div class="action-log-item">Episode started.</div>';
  document.getElementById('output').textContent = JSON.stringify(d, null, 2);
  renderAlerts(d.active_alerts || []);
  renderSysState(d.system_state || {});
  renderSuggestion(recommendAction(d));
  document.getElementById('scoreDisplay').textContent = '—';
  setScoreDonut(0);
  document.getElementById('scoreDetail').textContent = 'Grade will calculate after episode.';
  pushFeedItem('Environment initialized', 'info');
  appendActionTimeline(`reset ${document.getElementById('taskSel').value}`);
  flashStatus('STREAM ACTIVE', 'var(--accent-primary)');
  setTimeout(() => setPanelsLoading(false), 650);
}

async function doStep(autoScore = true) {
  if (episodeDone) {
    appendActionTimeline('step skipped (episode already done)');
    return;
  }
  flashStatus('EXECUTING...');
  const atype = document.getElementById('actionType').value;
  const rawTarget = document.getElementById('actionTarget').value;
  const target = rawTarget ? rawTarget.trim() : null;
  const reason = document.getElementById('actionReason').value || null;
  const body = { action: { action_type: atype, target: target, reason: reason, confidence: 1.0 } };
  const r = await fetch('/step', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const d = await r.json();
  if (!r.ok) {
    flashStatus('STEP FAILED', 'var(--accent-danger)');
    document.getElementById('output').textContent = JSON.stringify(d, null, 2);
    appendActionTimeline(`step failed ${atype}`);
    return;
  }
  actionHistory.add(`${atype}:${String(target || 'system').toLowerCase()}`);
  document.getElementById('output').textContent = JSON.stringify(d, null, 2);
  if (d.observation) {
    currentObservation = d.observation;
    renderAlerts(d.observation.active_alerts || []);
    renderSysState(d.observation.system_state || {});
    renderSuggestion(recommendAction(d.observation));
  }
  appendActionTimeline(`step ${atype} ${target || 'system'}`, d.reward);
  pushFeedItem(`Action executed: ${atype}`, 'low');
  flashStatus('READY');
  episodeDone = Boolean(d.done);
  if (episodeDone && autoScore) await doScore();
}

async function doScore() {
  if (!currentObservation) return;
  flashStatus('GRADING...', 'var(--accent-warning)');
  const r = await fetch('/score');
  const d = await r.json();
  if (!r.ok) {
    flashStatus('GRADE FAILED', 'var(--accent-danger)');
    document.getElementById('output').textContent = JSON.stringify(d, null, 2);
    appendActionTimeline('score failed');
    return;
  }
  const pct = Math.round((d.score || 0) * 100);
  animateCount('scoreDisplay', 0, pct, '%');
  setScoreDonut(pct);

  let detail = '';
  if (d.explanation && typeof d.explanation === 'object') {
    const tp = d.explanation.true_positives ? d.explanation.true_positives.length : (d.explanation.correct_detections || 0);
    const fp = d.explanation.false_positives || 0;
    const fn = d.explanation.missed_threats ? d.explanation.missed_threats.length : 0;
    detail = `TP ${tp} / FP ${fp} / FN ${fn}`;
    if (d.red_score !== undefined) detail += ` | Red Evades ${d.red_score}`;
  } else if (d.explanation) {
    detail = String(d.explanation);
  }
  document.getElementById('scoreDetail').textContent = detail;
  appendActionTimeline(`score ${pct}%`);
  pushFeedItem(`Episode score: ${pct}%`, pct < 40 ? 'critical' : pct < 70 ? 'medium' : 'low');
  flashStatus('EVALUATED', 'var(--accent-success)');
}

async function runAutonomousDemo() {
  if (demoRunning) return;
  demoRunning = true;
  setAutoStep('AUTO');
  flashStatus('AUTO DEMO RUNNING', 'var(--accent-warning)');
  try {
    await doReset();
    for (let i = 0; i < 6; i++) {
      if (!currentObservation || episodeDone) break;
      const next = recommendAction(currentObservation);
      if (!next) {
        appendActionTimeline('auto demo: no more high-confidence actions');
        break;
      }
      renderSuggestion(next);
      await doStep(false);
      if (!currentObservation || episodeDone) break;
    }
    await doScore();
  } catch (err) {
    appendActionTimeline('auto demo error');
  } finally {
    demoRunning = false;
    setAutoStep('MANUAL');
  }
}

function updateTarget() {
  const t = document.getElementById('actionType').value;
  const disabled = ['escalate_alert', 'ignore'].includes(t);
  document.getElementById('actionTarget').disabled = disabled;
  if (disabled) document.getElementById('actionTarget').value = '';
}

function initSidebarToggle() {
  const btn = document.getElementById('toggleSidebarBtn');
  const side = document.getElementById('sidebar');
  btn.addEventListener('click', () => {
    side.classList.toggle('collapsed');
    btn.textContent = side.classList.contains('collapsed') ? 'Expand' : 'Collapse';
  });
}

function init() {
  setupSorting();
  renderFeed();
  renderTimeline();
  renderAreaChart();
  renderSeverityBars();
  renderSparkline('sparkRisk', metricHistory.risk, 'var(--accent-danger)');
  renderSparkline('sparkConn', metricHistory.conn, 'var(--accent-primary)');
  renderSparkline('sparkBlocked', metricHistory.blocked, 'var(--accent-warning)');
  renderSparkline('sparkIsolated', metricHistory.isolated, 'var(--accent-success)');
  initSidebarToggle();
  updateTarget();
  setAutoStep('MANUAL');
  document.getElementById('taskSel').addEventListener('change', () => {
    if (currentObservation) renderSuggestion(recommendAction(currentObservation));
  });
  pushFeedItem('Console ready', 'info');
}
init();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port, reload=False)

if __name__ == "__main__":
    main()