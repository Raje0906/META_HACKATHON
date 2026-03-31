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
from models import SOCAction, SOCObservation, SOCState


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


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task_id: str = "easy_phishing_login"
    episode_id: Optional[str] = None
    seed: Optional[int] = None


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
async def reset(request: ResetRequest):
    """
    Reset the environment and start a new episode.

    **task_id options:**
    - `easy_phishing_login`     — Detect phishing + malicious login
    - `medium_brute_force_geo`  — Correlate brute-force + geo-anomaly
    - `hard_apt_multistage`     — Multi-stage APT kill chain
    """
    try:
        obs = _env.reset(
            task_id=request.task_id,
            episode_id=request.episode_id,
            seed=request.seed,
        )
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
        return {"score": final_score, "explanation": explanation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Optional Web UI
# ---------------------------------------------------------------------------

ENABLE_WEB = os.getenv("ENABLE_WEB_INTERFACE", "false").lower() == "true"


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
    """Build the interactive SOC dashboard HTML."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SOC Simulator — Interactive Dashboard</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d1117;color:#e6edf3;font-family:'Consolas',monospace;min-height:100vh}
    header{background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
    header h1{font-size:1.2rem;color:#58a6ff}
    .badge{background:#1f6feb;color:#fff;padding:2px 8px;border-radius:12px;font-size:0.7rem}
    .container{display:grid;grid-template-columns:1fr 1fr;gap:1rem;padding:1rem 2rem;max-width:1400px;margin:0 auto}
    .panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem}
    .panel h2{color:#58a6ff;font-size:0.9rem;margin-bottom:0.75rem;border-bottom:1px solid #21262d;padding-bottom:0.4rem}
    select,input,textarea{background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:4px;padding:6px 10px;width:100%;font-family:monospace;font-size:0.85rem;margin-bottom:0.5rem}
    button{background:#238636;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:0.85rem;width:100%}
    button:hover{background:#2ea043}
    button.danger{background:#da3633}button.danger:hover{background:#f85149}
    pre{background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:0.75rem;font-size:0.75rem;overflow-x:auto;white-space:pre-wrap;max-height:400px;overflow-y:auto}
    .alert{border-radius:4px;padding:0.5rem 0.75rem;margin-bottom:0.5rem;font-size:0.8rem}
    .critical{background:#3d1f28;border-left:3px solid #f85149}
    .high{background:#271e0a;border-left:3px solid #d29922}
    .info{background:#0d2137;border-left:3px solid #58a6ff}
    .score-bar{background:#21262d;border-radius:4px;height:20px;margin-top:0.5rem}
    .score-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#238636,#3fb950);transition:width 0.5s}
    label{font-size:0.8rem;color:#8b949e;display:block;margin-bottom:2px}
  </style>
</head>
<body>
<header>
  <h1>🛡 SOC Simulator</h1>
  <span class="badge">OpenEnv v1.0</span>
  <span class="badge" style="background:#6e40c9">AI Cybersecurity</span>
</header>
<div class="container">
  <div class="panel">
    <h2>🔄 Environment Control</h2>
    <label>Task</label>
    <select id="taskSel">
      <option value="easy_phishing_login">EASY — Phishing + Malicious Login</option>
      <option value="medium_brute_force_geo">MEDIUM — Brute Force + Geo Anomaly</option>
      <option value="hard_apt_multistage">HARD — Multi-Stage APT Attack</option>
    </select>
    <button onclick="doReset()">▶ Reset Environment</button>
    <hr style="border-color:#30363d;margin:0.75rem 0"/>
    <label>Action Type</label>
    <select id="actionType" onchange="updateTarget()">
      <option value="block_ip">block_ip</option>
      <option value="flag_user">flag_user</option>
      <option value="isolate_host">isolate_host</option>
      <option value="escalate_alert">escalate_alert</option>
      <option value="ignore">ignore</option>
    </select>
    <label>Target (IP / user / host)</label>
    <input id="actionTarget" placeholder="e.g. 185.220.101.47"/>
    <label>Reason (optional)</label>
    <input id="actionReason" placeholder="e.g. Suspicious geo-anomaly"/>
    <button onclick="doStep()">⚡ Take Action</button>
    <hr style="border-color:#30363d;margin:0.75rem 0"/>
    <button class="danger" onclick="doScore()">📊 Grade Episode</button>
  </div>
  <div class="panel">
    <h2>📋 Active Alerts</h2>
    <div id="alertsDiv"><em style="color:#8b949e">Reset to load alerts...</em></div>
    <h2 style="margin-top:1rem">🖥 System State</h2>
    <div id="sysState"><em style="color:#8b949e">Reset to load state...</em></div>
  </div>
  <div class="panel" style="grid-column:1/-1">
    <h2>📄 Latest Response</h2>
    <pre id="output">Press "Reset Environment" to begin...</pre>
  </div>
  <div class="panel">
    <h2>🏆 Score</h2>
    <div id="scoreDisplay" style="font-size:2rem;font-weight:bold;color:#3fb950">—</div>
    <div class="score-bar"><div class="score-fill" id="scoreBar" style="width:0%"></div></div>
    <pre id="scoreDetail" style="margin-top:0.75rem">Grade after episode ends.</pre>
  </div>
</div>
<script>
async function doReset(){
  const r=await fetch('/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({task_id:document.getElementById('taskSel').value})});
  const d=await r.json();
  document.getElementById('output').textContent=JSON.stringify(d,null,2);
  renderAlerts(d.active_alerts||[]);
  renderSysState(d.system_state||{});
  document.getElementById('scoreDisplay').textContent='—';
  document.getElementById('scoreBar').style.width='0%';
  document.getElementById('scoreDetail').textContent='';
}
async function doStep(){
  const atype=document.getElementById('actionType').value;
  const target=document.getElementById('actionTarget').value||null;
  const reason=document.getElementById('actionReason').value||null;
  const body={action:{action_type:atype,target:target,reason:reason,confidence:1.0}};
  const r=await fetch('/step',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  document.getElementById('output').textContent=JSON.stringify(d,null,2);
  if(d.observation){renderAlerts(d.observation.active_alerts||[]);renderSysState(d.observation.system_state||{});}
  if(d.done)doScore();
}
async function doScore(){
  const r=await fetch('/score');const d=await r.json();
  const pct=Math.round((d.score||0)*100);
  document.getElementById('scoreDisplay').textContent=pct+'%';
  document.getElementById('scoreBar').style.width=pct+'%';
  document.getElementById('scoreDetail').textContent=JSON.stringify(d.explanation,null,2);
}
function renderAlerts(alerts){
  const div=document.getElementById('alertsDiv');
  if(!alerts.length){div.innerHTML='<em style="color:#8b949e">No active alerts</em>';return;}
  div.innerHTML=alerts.map(a=>`<div class="alert ${a.threat_level}"><strong>[${a.threat_level.toUpperCase()}]</strong> ${a.title}<br/><small>${a.description.slice(0,120)}...</small></div>`).join('');
}
function renderSysState(s){
  document.getElementById('sysState').innerHTML=`
    <div style="font-size:0.8rem;line-height:1.8">
    🔴 Risk Score: <strong>${((s.risk_score||0)*100).toFixed(0)}%</strong><br/>
    🚫 Blocked IPs: <strong>${(s.blocked_ips||[]).join(', ')||'none'}</strong><br/>
    🚩 Flagged Users: <strong>${(s.flagged_users||[]).join(', ')||'none'}</strong><br/>
    🔒 Isolated Hosts: <strong>${(s.isolated_hosts||[]).join(', ')||'none'}</strong><br/>
    📡 Active Connections: <strong>${s.active_connections||0}</strong>
    </div>`;
}
function updateTarget(){const t=document.getElementById('actionType').value;document.getElementById('actionTarget').disabled=['escalate_alert','ignore'].includes(t);}
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
