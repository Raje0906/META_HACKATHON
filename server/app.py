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
    """Build the interactive SOC dashboard HTML with a premium aesthetic."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SOC Simulator — Threat Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0a0e17;
      --panel-bg: rgba(16, 22, 35, 0.7);
      --glass-border: rgba(255, 255, 255, 0.08);
      --accent-blue: #3b82f6;
      --accent-cyan: #06b6d4;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #111827 0%, var(--bg) 100%);
      color: var(--text-main);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
    }
    header {
      background: rgba(10, 14, 23, 0.8);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--glass-border);
      padding: 1.2rem 3rem;
      display: flex;
      align-items: center;
      gap: 1.5rem;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    header h1 {
      font-size: 1.4rem;
      font-weight: 700;
      background: linear-gradient(90deg, #60a5fa, #34d399);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
    }
    .badge {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      border: 1px solid rgba(59, 130, 246, 0.3);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .container {
      display: grid;
      grid-template-columns: 350px 1fr 300px;
      gap: 1.5rem;
      padding: 2rem 3rem;
      max-width: 1800px;
      margin: 0 auto;
    }
    .panel {
      background: var(--panel-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--glass-border);
      border-radius: 16px;
      padding: 1.5rem;
      box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .panel h2 {
      color: var(--text-main);
      font-size: 1.05rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .panel h2::before {
      content: '';
      display: block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-cyan);
      box-shadow: 0 0 8px var(--accent-cyan);
    }
    select, input, textarea {
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid rgba(255, 255, 255, 0.1);
      color: var(--text-main);
      border-radius: 8px;
      padding: 10px 12px;
      width: 100%;
      font-family: inherit;
      font-size: 0.9rem;
      transition: all 0.2s ease;
      outline: none;
    }
    select:focus, input:focus {
      border-color: var(--accent-blue);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }
    button {
      background: linear-gradient(135deg, var(--accent-blue), #2563eb);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 10px 16px;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 600;
      width: 100%;
      transition: all 0.2s ease;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(37, 99, 235, 0.4);
    }
    button.danger {
      background: linear-gradient(135deg, var(--danger), #dc2626);
      box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
    }
    button.danger:hover {
      box-shadow: 0 6px 16px rgba(239, 68, 68, 0.4);
    }
    button.outline {
      background: transparent;
      border: 1px solid var(--glass-border);
      box-shadow: none;
    }
    button.outline:hover {
      background: rgba(255,255,255,0.05);
      border-color: rgba(255,255,255,0.2);
    }
    pre {
      background: #000;
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      padding: 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #a5b4fc;
      overflow-y: auto;
      height: 100%;
      min-height: 400px;
    }
    .alert {
      border-radius: 8px;
      padding: 0.75rem 1rem;
      font-size: 0.85rem;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--glass-border);
      animation: slideIn 0.3s ease forwards;
    }
    @keyframes slideIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .critical { border-left: 4px solid var(--danger); }
    .high { border-left: 4px solid var(--warning); }
    .info { border-left: 4px solid var(--accent-blue); }
    .alert-title { font-weight: 600; margin-bottom: 4px; display: block; }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 0.75rem;
    }
    .stat-card {
      background: rgba(0,0,0,0.2);
      padding: 0.75rem;
      border-radius: 8px;
    }
    .stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
    .stat-value { font-family: 'JetBrains Mono', monospace; font-size: 1.1rem; font-weight: 700; margin-top: 4px; color: var(--text-main); }
    
    .score-container {
      text-align: center;
      padding: 2rem 0;
    }
    .score-circle {
      width: 120px;
      height: 120px;
      border-radius: 50%;
      background: conic-gradient(var(--success) var(--pct), rgba(255,255,255,0.05) 0);
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }
    .score-circle::before {
      content: '';
      position: absolute;
      inset: 8px;
      background: var(--bg);
      border-radius: 50%;
    }
    .score-text {
      position: relative;
      font-size: 2rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }
    label { font-size: 0.8rem; font-weight: 500; color: var(--text-muted); margin-bottom: -0.5rem; }
    
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }
  </style>
</head>
<body>
<header>
  <h1>🛡 SOC Simulator</h1>
  <span class="badge">Live Telemetry</span>
  <span class="badge" style="border-color:rgba(16, 185, 129, 0.3); color: #10b981; background: rgba(16, 185, 129, 0.1);">System Online</span>
</header>
<div class="container">
  
  <!-- Left Panel: Controls -->
  <div class="panel">
    <h2>Environment Controls</h2>
    <label>Scenario / Task</label>
    <select id="taskSel">
      <option value="easy_phishing_login">EASY — Phishing Campaign</option>
      <option value="medium_brute_force_geo">MEDIUM — Geo-Anomaly</option>
      <option value="hard_apt_multistage">HARD — APT Kill Chain</option>
    </select>
    <button class="outline" onclick="doReset()">🔄 Initialize Environment</button>
    
    <div style="height:1px; background:var(--glass-border); margin:0.5rem 0;"></div>
    
    <h2>Response Center</h2>
    <label>Action Primitive</label>
    <select id="actionType" onchange="updateTarget()">
      <option value="block_ip">block_ip</option>
      <option value="flag_user">flag_user</option>
      <option value="isolate_host">isolate_host</option>
      <option value="escalate_alert">escalate_alert</option>
      <option value="ignore">ignore</option>
    </select>
    <label>Entity Target</label>
    <input id="actionTarget" placeholder="e.g. 185.220.101.47"/>
    <label>Audit Reason (Optional)</label>
    <input id="actionReason" placeholder="e.g. Suspicious geo-travel"/>
    <button onclick="doStep()">⚡ Execute Action</button>
    
    <button class="danger" onclick="doScore()" style="margin-top: 1.5rem;">📊 Evaluate Episode</button>
  </div>
  
  <!-- Center Panel: JSON Output & Alerts -->
  <div class="panel" style="display:grid; grid-template-rows: auto 1fr; gap:1.5rem;">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2>Raw Event Stream</h2>
      <span style="font-size:0.8rem; color:var(--text-muted); font-family:monospace" id="statusIndicator">Awaiting connection...</span>
    </div>
    <pre id="output">Initialize the environment to begin stream capture...</pre>
  </div>
  
  <!-- Right Panel: Intelligence -->
  <div class="panel" style="gap:1.5rem;">
    <h2>Actionable Alerts</h2>
    <div id="alertsDiv" style="display:flex; flex-direction:column; gap:0.5rem; max-height:250px; overflow-y:auto;">
      <em style="color:var(--text-muted); font-size:0.85rem;">No active anomalies detected.</em>
    </div>
    
    <h2>Network State</h2>
    <div id="sysState" class="stats-grid">
      <div class="stat-card"><div class="stat-label">Risk Level</div><div class="stat-value" id="riskScore">0%</div></div>
      <div class="stat-card"><div class="stat-label">Connections</div><div class="stat-value" id="activeConn">0</div></div>
      <div class="stat-card" style="grid-column:1/-1;"><div class="stat-label">Isolated Hosts</div><div class="stat-value" style="font-size:0.85rem" id="isolatedHosts">None</div></div>
      <div class="stat-card" style="grid-column:1/-1;"><div class="stat-label">Blocked IPs</div><div class="stat-value" style="font-size:0.85rem" id="blockedIps">None</div></div>
    </div>
    
    <h2>Evaluation Score</h2>
    <div class="score-container">
      <div class="score-circle" id="scoreCircle" style="--pct:0%">
        <span class="score-text" id="scoreDisplay">—</span>
      </div>
      <p id="scoreDetail" style="margin-top:1rem; font-size:0.8rem; color:var(--text-muted);"></p>
    </div>
  </div>
  
</div>

<script>
function flashStatus(msg) {
  const el = document.getElementById('statusIndicator');
  el.textContent = msg;
  el.style.color = '#34d399';
  setTimeout(()=> el.style.color = 'var(--text-muted)', 1500);
}

async function doReset(){
  flashStatus('Resetting environment...');
  const r=await fetch('/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_id:document.getElementById('taskSel').value})});
  const d=await r.json();
  document.getElementById('output').textContent=JSON.stringify(d,null,2);
  renderAlerts(d.active_alerts||[]);
  renderSysState(d.system_state||{});
  document.getElementById('scoreDisplay').textContent='—';
  document.getElementById('scoreCircle').style.setProperty('--pct', '0%');
  document.getElementById('scoreDetail').textContent='Grade will calculate after episode.';
  flashStatus('Stream active');
}

async function doStep(){
  flashStatus('Executing action...');
  const atype=document.getElementById('actionType').value;
  const rawTarget=document.getElementById('actionTarget').value;
  const target=rawTarget ? rawTarget.trim() : null;
  const reason=document.getElementById('actionReason').value||null;
  const body={action:{action_type:atype,target:target,reason:reason,confidence:1.0}};
  const r=await fetch('/step',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  document.getElementById('output').textContent=JSON.stringify(d,null,2);
  if(d.observation){
    renderAlerts(d.observation.active_alerts||[]);
    renderSysState(d.observation.system_state||{});
  }
  flashStatus('Ready');
  if(d.done) doScore();
}

async function doScore(){
  flashStatus('Grading...');
  const r=await fetch('/score');
  const d=await r.json();
  const pct=Math.round((d.score||0)*100);
  document.getElementById('scoreDisplay').textContent=pct+'%';
  
  // Update conic gradient color dynamically based on score
  const color = pct > 80 ? '#10b981' : pct > 40 ? '#f59e0b' : '#ef4444';
  const circle = document.getElementById('scoreCircle');
  circle.style.background = `conic-gradient(${color} ${pct}%, rgba(255,255,255,0.05) 0)`;
  
  let detailHTML = "";
  if (d.explanation) {
    if (typeof d.explanation === 'object') {
      const tp = d.explanation.true_positives ? d.explanation.true_positives.length : (d.explanation.correct_detections || 0);
      const fp = d.explanation.false_positives || 0;
      const fn = d.explanation.missed_threats ? d.explanation.missed_threats.length : 0;
      detailHTML = `<b>True Positives (Hits):</b> ${tp} <br/> <b>False Positives (Mistakes):</b> ${fp} <br/> <b>Undetected (Misses):</b> ${fn}`;
      if (d.red_score !== undefined) {
         detailHTML += `<br/><br/><span style="color:var(--danger)"><b>🔴 Red Agent Successful Evades:</b> ${d.red_score}</span>`;
      }
    } else {
      detailHTML = d.explanation;
    }
  }
  document.getElementById('scoreDetail').innerHTML = detailHTML;
  flashStatus('Evaluated');
}

function renderAlerts(alerts){
  const div=document.getElementById('alertsDiv');
  if(!alerts.length){div.innerHTML='<em style="color:var(--text-muted); font-size:0.85rem;">No active anomalies detected.</em>';return;}
  div.innerHTML=alerts.map(a=>`
    <div class="alert ${a.threat_level}">
      <span class="alert-title">[${a.threat_level.toUpperCase()}] ${a.title}</span>
      <span style="color:var(--text-muted); font-size:0.8rem; line-height:1.4">${a.description}</span>
    </div>
  `).join('');
}

function renderSysState(s){
  document.getElementById('riskScore').textContent = ((s.risk_score||0)*100).toFixed(0)+'%';
  document.getElementById('activeConn').textContent = s.active_connections||0;
  document.getElementById('isolatedHosts').textContent = (s.isolated_hosts||[]).join(', ')||'None';
  document.getElementById('blockedIps').textContent = (s.blocked_ips||[]).join(', ')||'None';
}

function updateTarget(){
  const t=document.getElementById('actionType').value;
  document.getElementById('actionTarget').disabled=['escalate_alert','ignore'].includes(t);
  if (['escalate_alert','ignore'].includes(t)) document.getElementById('actionTarget').value = '';
}
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
