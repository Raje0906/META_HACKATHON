import re

with open("server/app.py", "r", encoding="utf-8") as f:
    content = f.read()

new_html = r'''def _build_web_ui() -> str:
    """Build a fully redesigned, judge-ready SOC dashboard."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>SOC Simulator — Judge Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vanilla-tilt/1.8.1/vanilla-tilt.min.js"></script>
  <style>
    :root {
      --bg0: #030712;
      --bg1: #0b1120;
      --card-bg: rgba(11, 17, 32, 0.45);
      --card-border: rgba(59, 130, 246, 0.2);
      --card-border-hover: rgba(59, 130, 246, 0.5);
      --text: #f8fafc;
      --muted: #94a3b8;
      --brand: #3b82f6;
      --brand-glow: rgba(59, 130, 246, 0.6);
      --cyan: #06b6d4;
      --green: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --radius: 16px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; overflow: hidden; background: var(--bg0); font-family: 'Outfit', sans-serif; color: var(--text); }

    /* 3D Background Canvas */
    #canvas-container {
      position: absolute;
      top: 0; left: 0; width: 100vw; height: 100vh;
      z-index: -1;
      overflow: hidden;
    }

    /* Top Navigation */
    .topbar {
      position: relative; z-index: 10;
      display: flex; align-items: center; justify-content: space-between;
      padding: 1rem 2rem;
      background: linear-gradient(180deg, rgba(3,7,18,0.9) 0%, rgba(3,7,18,0) 100%);
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    .brand { font-size: 1.5rem; font-weight: 800; display: flex; align-items: center; gap: 0.8rem; letter-spacing: 1px; }
    .brand-icon {
      width: 24px; height: 24px; border-radius: 4px;
      background: linear-gradient(135deg, var(--brand), var(--cyan));
      box-shadow: 0 0 15px var(--brand-glow);
      animation: pulse 2s infinite;
    }

    /* Main Container */
    .shell {
      position: relative; z-index: 10;
      height: calc(100vh - 70px);
      overflow-y: auto;
      padding: 2rem;
      scroll-behavior: smooth;
    }
    
    .shell::-webkit-scrollbar { width: 8px; }
    .shell::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }

    /* Layout Grid */
    .grid {
      display: grid;
      grid-template-columns: 320px 1fr 350px;
      gap: 1.5rem;
      max-width: 1600px; margin: 0 auto;
    }

    /* Glassmorphism Cards */
    .glass-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 1.5rem;
      box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
      transform-style: preserve-3d;
    }
    .glass-card:hover {
      border-color: var(--card-border-hover);
      box-shadow: 0 8px 32px 0 rgba(59, 130, 246, 0.15);
    }
    
    .glass-card h3 {
      font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem;
      display: flex; align-items: center; gap: 0.5rem;
      text-transform: uppercase; letter-spacing: 1px; color: var(--cyan);
      transform: translateZ(20px);
    }
    
    .card-content { transform: translateZ(10px); }

    /* Hero Section */
    .hero { grid-column: 1 / -1; display: grid; grid-template-columns: auto 1fr; gap: 2rem; align-items: center; }
    .hero-title { font-size: 2.5rem; font-weight: 800; background: linear-gradient(135deg, #fff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero-stats { display: flex; gap: 1rem; }
    .stat-badge {
      background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
      padding: 0.75rem 1.5rem; border-radius: 12px; text-align: center;
      box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
    }
    .stat-badge .k { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
    .stat-badge .v { font-size: 1.5rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; color: var(--brand); text-shadow: 0 0 10px var(--brand-glow); }

    /* Form Elements */
    .control-group { margin-bottom: 1rem; }
    label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.4rem; text-transform: uppercase; letter-spacing: 0.5px;}
    select, input {
      width: 100%; padding: 0.8rem; border-radius: 8px;
      background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1);
      color: var(--text); font-family: 'Outfit', sans-serif;
      transition: all 0.3s ease;
    }
    select:focus, input:focus { outline: none; border-color: var(--cyan); box-shadow: 0 0 15px rgba(6, 182, 212, 0.3); }
    
    /* Buttons */
    .btn {
      width: 100%; padding: 0.8rem; border-radius: 8px; border: none; cursor: pointer;
      font-family: 'Outfit', sans-serif; font-weight: 600; font-size: 1rem;
      color: #fff; background: linear-gradient(135deg, var(--brand), #1d4ed8);
      position: relative; overflow: hidden;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn::before {
      content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s;
    }
    .btn:hover::before { left: 100%; }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(59, 130, 246, 0.4); }
    .btn.secondary { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); }
    .btn.secondary:hover { background: rgba(255,255,255,0.1); }
    .btn.danger { background: linear-gradient(135deg, var(--red), #991b1b); }
    .btn.danger:hover { box-shadow: 0 10px 20px rgba(239, 68, 68, 0.4); }

    /* Stream Console */
    .console-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .status-pulse { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: var(--green); }
    .status-pulse .dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 10px var(--green); animation: pulse 1.5s infinite; }
    
    .stream-box {
      background: rgba(0,0,0,0.6); border: 1px solid rgba(255,255,255,0.05);
      border-radius: 8px; padding: 1rem; height: 350px; overflow-y: auto;
      font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #60a5fa;
      box-shadow: inset 0 0 20px rgba(0,0,0,0.8);
    }
    .stream-box::-webkit-scrollbar { width: 5px; }
    .stream-box::-webkit-scrollbar-thumb { background: rgba(59, 130, 246, 0.3); }
    
    .timeline { margin-top: 1rem; background: rgba(0,0,0,0.4); border-radius: 8px; padding: 1rem; height: 200px; overflow-y: auto; }
    .log-line { display: flex; gap: 1rem; margin-bottom: 0.5rem; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }
    .log-time { color: var(--muted); }
    .log-msg { color: #cbd5e1; }
    .log-msg.highlight { color: var(--amber); }

    /* Alerts */
    .alert-card {
      background: rgba(255,255,255,0.02); border-left: 4px solid var(--brand);
      border-radius: 4px 8px 8px 4px; padding: 1rem; margin-bottom: 0.8rem;
      cursor: pointer; transition: all 0.2s ease;
    }
    .alert-card:hover { background: rgba(255,255,255,0.05); transform: translateX(5px); }
    .alert-card.critical { border-left-color: var(--red); }
    .alert-card.high { border-left-color: var(--amber); }
    .alert-card .title { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.3rem; }
    .alert-card .desc { font-size: 0.8rem; color: var(--muted); }

    /* Score Ring */
    .score-container { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 1rem 0; }
    .circular-chart { display: block; margin: 0 auto; max-width: 160px; max-height: 160px; }
    .circle-bg { fill: none; stroke: rgba(255,255,255,0.05); stroke-width: 3.8; }
    .circle { 
      fill: none; stroke-width: 3.8; stroke-linecap: round; 
      transition: stroke-dasharray 1.5s ease-out, stroke 0.5s ease;
    }
    .percentage { fill: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 0.6em; text-anchor: middle; font-weight: 800; }
    .score-details { text-align: center; margin-top: 1rem; font-size: 0.9rem; color: var(--muted); }

    /* Toggle Switch */
    .switch-container { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.8rem; font-size: 0.85rem; }
    .switch { position: relative; display: inline-block; width: 40px; height: 20px; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: rgba(255,255,255,0.1); transition: .4s; border-radius: 34px; }
    .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: white; transition: .4s; border-radius: 50%; }
    input:checked + .slider { background-color: var(--brand); box-shadow: 0 0 10px var(--brand-glow); }
    input:checked + .slider:before { transform: translateX(20px); }

    @keyframes pulse { 0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.7); } 70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(59, 130, 246, 0); } 100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(59, 130, 246, 0); } }
  </style>
</head>
<body>

  <!-- 3D Background -->
  <div id="canvas-container"></div>

  <!-- Topbar -->
  <div class="topbar">
    <div class="brand"><div class="brand-icon"></div> SOC SIMULATOR</div>
    <div style="display:flex;gap:1rem;align-items:center;">
      <span style="font-size:0.8rem;color:var(--brand);text-transform:uppercase;letter-spacing:1px;" id="globalStatus">System Online</span>
      <div class="stat-badge" style="padding:0.4rem 1rem;"><div class="v" style="font-size:1rem;" id="heroScore">--%</div></div>
    </div>
  </div>

  <!-- Main App Shell -->
  <div class="shell">
    <div class="grid">
      
      <!-- Left Panel: Controls -->
      <div class="glass-card" data-tilt data-tilt-max="2" data-tilt-speed="400" data-tilt-glare data-tilt-max-glare="0.1">
        <div class="card-content">
          <h3>Environment</h3>
          <div class="control-group">
            <label>Scenario Vector</label>
            <select id="taskSel">
              <option value="easy_phishing_login">EASY — Phishing Campaign</option>
              <option value="medium_brute_force_geo">MEDIUM — Geo-Anomaly</option>
              <option value="hard_apt_multistage">HARD — APT Kill Chain</option>
            </select>
          </div>
          
          <div class="switch-container">
            <span>Deterministic Mode</span>
            <label class="switch"><input type="checkbox" id="deterministicDemo" checked><span class="slider"></span></label>
          </div>
          <div class="switch-container">
            <span>Judge View (Hide JSON)</span>
            <label class="switch"><input type="checkbox" id="judgeMode" checked><span class="slider"></span></label>
          </div>
          
          <button class="btn secondary" onclick="doReset()" style="margin-top:0.5rem;margin-bottom:1rem;">INITIALIZE ENVIRONMENT</button>
          <button class="btn" onclick="runAutonomousDemo()" style="margin-bottom:2rem;">RUN AUTONOMOUS DEMO</button>

          <h3>Manual Override</h3>
          <div class="control-group">
            <label>Action Primitive</label>
            <select id="actionType" onchange="updateTarget()">
              <option value="block_ip">block_ip</option>
              <option value="flag_user">flag_user</option>
              <option value="isolate_host">isolate_host</option>
              <option value="escalate_alert">escalate_alert</option>
              <option value="ignore">ignore</option>
            </select>
          </div>
          <div class="control-group">
            <label>Entity Target</label>
            <input type="text" id="actionTarget" placeholder="e.g. 185.220.101.47" />
          </div>
          <button class="btn" onclick="doStep()" style="margin-bottom:0.5rem;">EXECUTE ACTION</button>
          <button class="btn danger" onclick="doScore()">EVALUATE EPISODE</button>
        </div>
      </div>

      <!-- Center Panel: Telemetry -->
      <div class="glass-card" data-tilt data-tilt-max="1" data-tilt-speed="400">
        <div class="card-content">
          <div class="console-header">
            <h3>Live Telemetry Stream</h3>
            <div class="status-pulse" id="streamStatus"><div class="dot"></div>Awaiting Init</div>
          </div>
          <div class="stream-box" id="output">Waiting for environment initialization...</div>
          
          <h3 style="margin-top: 1.5rem;">Action Timeline</h3>
          <div class="timeline" id="demoTimeline"></div>
        </div>
      </div>

      <!-- Right Panel: Intelligence -->
      <div class="glass-card" data-tilt data-tilt-max="2" data-tilt-speed="400" data-tilt-glare data-tilt-max-glare="0.1">
        <div class="card-content">
          <h3>Active Threats</h3>
          <div id="alertsDiv" style="min-height:100px; max-height:250px; overflow-y:auto; margin-bottom:1.5rem;">
            <div style="color:var(--muted);font-size:0.85rem;text-align:center;padding:1rem;">No active anomalies.</div>
          </div>

          <h3>Evaluation Core</h3>
          <div class="score-container">
            <svg viewBox="0 0 36 36" class="circular-chart">
              <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
              <path class="circle" id="scoreCircle" strokeDasharray="0, 100" stroke="var(--cyan)" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
              <text x="18" y="20.35" class="percentage" id="scoreDisplay">0%</text>
            </svg>
            <div class="score-details" id="scoreDetail">Grade pending.</div>
          </div>
          
          <h3 style="margin-top:1.5rem;">Network State</h3>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
            <div style="background:rgba(0,0,0,0.3);padding:0.8rem;border-radius:8px;">
              <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;">Risk Level</div>
              <div style="font-size:1.2rem;font-weight:700;color:var(--amber);" id="riskScore">0%</div>
            </div>
            <div style="background:rgba(0,0,0,0.3);padding:0.8rem;border-radius:8px;">
              <div style="font-size:0.7rem;color:var(--muted);text-transform:uppercase;">Connections</div>
              <div style="font-size:1.2rem;font-weight:700;color:var(--text);" id="activeConn">0</div>
            </div>
          </div>
          
        </div>
      </div>
      
    </div>
  </div>

  <script>
    // --- 3D Background Logic (Three.js) ---
    const init3D = () => {
      const container = document.getElementById('canvas-container');
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
      const renderer = new THREE.WebGLRenderer({alpha: true, antialias: true});
      renderer.setSize(window.innerWidth, window.innerHeight);
      container.appendChild(renderer.domElement);

      // Create a particle network
      const geometry = new THREE.BufferGeometry();
      const particlesCount = 1500;
      const posArray = new Float32Array(particlesCount * 3);
      for(let i=0; i<particlesCount*3; i++){
        posArray[i] = (Math.random() - 0.5) * 15;
      }
      geometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
      
      const material = new THREE.PointsMaterial({
        size: 0.02,
        color: 0x3b82f6,
        transparent: true,
        opacity: 0.8,
        blending: THREE.AdditiveBlending
      });
      
      const particlesMesh = new THREE.Points(geometry, material);
      scene.add(particlesMesh);
      camera.position.z = 3;

      let mouseX = 0;
      let mouseY = 0;
      document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX / window.innerWidth - 0.5;
        mouseY = e.clientY / window.innerHeight - 0.5;
      });

      const animate = () => {
        requestAnimationFrame(animate);
        particlesMesh.rotation.y += 0.001;
        particlesMesh.rotation.x += 0.0005;
        
        // Subtle mouse interaction
        camera.position.x += (mouseX * 0.5 - camera.position.x) * 0.05;
        camera.position.y += (-mouseY * 0.5 - camera.position.y) * 0.05;
        camera.lookAt(scene.position);
        
        renderer.render(scene, camera);
      };
      animate();

      window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
      });
    };
    init3D();

    // --- App Logic ---
    let currentObservation = null;
    let demoRunning = false;

    function setStatus(text, status='active') {
      const el = document.getElementById('streamStatus');
      el.innerHTML = `<div class="dot" style="background:${status==='error'?'var(--red)':status==='waiting'?'var(--amber)':'var(--green)'}; box-shadow:0 0 10px ${status==='error'?'var(--red)':status==='waiting'?'var(--amber)':'var(--green)'}"></div>${text}`;
    }

    function addTimeline(action, color='var(--text)') {
      const box = document.getElementById('demoTimeline');
      const time = new Date().toLocaleTimeString('en-US',{hour12:false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
      const div = document.createElement('div');
      div.className = 'log-line';
      div.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-msg" style="color:${color}">${action}</span>`;
      box.prepend(div);
    }

    function updateTarget() {
      const t = document.getElementById('actionType').value;
      const input = document.getElementById('actionTarget');
      const disabled = ['ignore','escalate_alert'].includes(t);
      input.disabled = disabled;
      if(disabled) input.value = '';
    }

    function applyJudgeMode(data) {
      const on = document.getElementById('judgeMode').checked;
      const out = document.getElementById('output');
      if(on) {
        if(data && data.recent_events) {
            let str = "## EVENTS ANALYZED ##\\n";
            data.recent_events.forEach(e => { str += `> ${e.event_id} | ${e.log_type} | src:${e.source_ip || e.remote_ip || 'N/A'}\\n`; });
            out.textContent = str;
        } else {
            out.textContent = "Data payload hidden in Judge Mode.";
        }
      } else {
        out.textContent = JSON.stringify(data, null, 2);
      }
    }

    function renderAlerts(alerts) {
      const box = document.getElementById('alertsDiv');
      if(!alerts || !alerts.length){
        box.innerHTML = '<div style="color:var(--muted);font-size:0.85rem;text-align:center;padding:1rem;">No active anomalies.</div>';
        return;
      }
      box.innerHTML = alerts.map(a => `
        <div class="alert-card ${(a.threat_level||'').toLowerCase()}" onclick="prefillAlert('${(a.related_events&&a.related_events[0])||''}')">
          <div class="title">[${(a.threat_level||'INFO').toUpperCase()}] ${a.title||'Alert'}</div>
          <div class="desc">${a.description||''}</div>
        </div>
      `).join('');
    }

    function prefillAlert(eventId) {
      if(!currentObservation || !eventId) return;
      const e = (currentObservation.recent_events || []).find(x => x.event_id === eventId);
      if(!e) return;
      const ip = e.remote_ip || e.source_ip || e.src_addr;
      const user = e.account_name || e.user_id || e.username;
      if(ip) { document.getElementById('actionType').value = 'block_ip'; document.getElementById('actionTarget').value = ip; }
      else if(user) { document.getElementById('actionType').value = 'flag_user'; document.getElementById('actionTarget').value = user; }
      updateTarget();
    }

    async function doReset() {
      setStatus('Initializing Core...', 'waiting');
      const task = document.getElementById('taskSel').value;
      const det = document.getElementById('deterministicDemo').checked;
      
      const payload = { task_id: task };
      if(det) payload.custom_params = { enable_red_agent: false, use_live_threat_intel: false, enable_schema_drift: false };

      try {
        const r = await fetch('/reset', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        currentObservation = d;
        applyJudgeMode(d);
        renderAlerts(d.active_alerts);
        document.getElementById('riskScore').textContent = `${Math.round((d.system_state?.risk_score||0)*100)}%`;
        document.getElementById('activeConn').textContent = d.system_state?.active_connections || 0;
        
        // Reset Score UI
        setScoreUI(0, 'var(--cyan)');
        document.getElementById('scoreDetail').textContent = 'Grade pending.';
        document.getElementById('demoTimeline').innerHTML = '';
        addTimeline(`System initialized: ${task}`, 'var(--cyan)');
        setStatus('Stream Active', 'active');
      } catch(e) { setStatus('Connection Error', 'error'); }
    }

    async function doStep() {
      setStatus('Executing...', 'waiting');
      const at = document.getElementById('actionType').value;
      const target = document.getElementById('actionTarget').value;
      
      const payload = { action: { action_type: at, target: target?target.trim():null, confidence: 1.0 } };
      try {
        const r = await fetch('/step', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        if(d.observation) {
          currentObservation = d.observation;
          applyJudgeMode(d.observation);
          renderAlerts(d.observation.active_alerts);
          document.getElementById('riskScore').textContent = `${Math.round((d.observation.system_state?.risk_score||0)*100)}%`;
          document.getElementById('activeConn').textContent = d.observation.system_state?.active_connections || 0;
        }
        addTimeline(`> ${at}(${payload.action.target||'sys'}) → Rew: ${Number(d.reward||0).toFixed(2)}`, 'var(--brand)');
        setStatus('Ready', 'active');
        if(d.done) await doScore();
      } catch(e) { setStatus('Step Failed', 'error'); }
    }

    function setScoreUI(pct, color) {
      document.getElementById('scoreDisplay').textContent = `${pct}%`;
      document.getElementById('heroScore').textContent = `${pct}%`;
      const circle = document.getElementById('scoreCircle');
      circle.style.strokeDasharray = `${pct}, 100`;
      circle.style.stroke = color;
    }

    async function doScore() {
      setStatus('Evaluating...', 'waiting');
      try {
        const r = await fetch('/score');
        const d = await r.json();
        const pct = Math.round((d.score||0)*100);
        const color = pct > 80 ? 'var(--green)' : pct > 40 ? 'var(--amber)' : 'var(--red)';
        
        setScoreUI(pct, color);
        
        let detail = typeof d.explanation==='object' 
          ? `Hits: ${d.explanation.correct_detections||0} | FP: ${d.explanation.false_positives||0}` 
          : 'Evaluated.';
        if(d.red_score !== undefined) detail += ` | Red Agent: ${Number(d.red_score).toFixed(3)}`;
        
        document.getElementById('scoreDetail').textContent = detail;
        addTimeline(`Episode Evaluated: Score ${pct}%`, color);
        setStatus('Evaluation Complete', 'active');
      } catch(e) { setStatus('Eval Failed', 'error'); }
    }

    // A simple mock of the python agent heuristic for the frontend demo
    function getRecommend(obs) {
        if(!obs) return {action_type:'ignore'};
        const alerts = obs.active_alerts || [];
        const events = obs.recent_events || [];
        for(let a of alerts) {
            if(a.threat_level==='critical' && a.related_events) {
                let e = events.find(x=>x.event_id===a.related_events[0]);
                if(e && e.host_id) return {action_type:'isolate_host', target:e.host_id};
            }
        }
        for(let a of alerts) {
            if(['high','critical'].includes(a.threat_level) && a.related_events) {
                let e = events.find(x=>x.event_id===a.related_events[0]);
                if(e && (e.remote_ip || e.source_ip)) return {action_type:'block_ip', target:e.remote_ip||e.source_ip};
            }
        }
        for(let e of events) {
            if(e.details?.mfa_bypassed) return {action_type:'flag_user', target:e.account_name||e.user_id};
        }
        return {action_type:'ignore'};
    }

    async function runAutonomousDemo() {
      if(demoRunning) return;
      demoRunning = true;
      setStatus('Autonomous Mode Engaged', 'waiting');
      try {
        await doReset();
        for(let i=0; i<10; i++) {
          if(!currentObservation || currentObservation.done) break;
          const rec = getRecommend(currentObservation);
          const payload = { action: { action_type: rec.action_type, target: rec.target, confidence: 1.0 } };
          const r = await fetch('/step', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          const d = await r.json();
          if(d.observation) { currentObservation = d.observation; renderAlerts(d.observation.active_alerts); }
          addTimeline(`Auto > ${rec.action_type}(${rec.target||'sys'})`, 'var(--cyan)');
          if(d.done) break;
          await new Promise(res => setTimeout(res, 600));
        }
        await doScore();
      } catch(e) {}
      demoRunning = false;
    }

    document.getElementById('judgeMode').addEventListener('change', () => applyJudgeMode(currentObservation));
  </script>
</body>
</html>
"""
'''

new_content = re.sub(
    r'def _build_web_ui\(\) -> str:.*?^"""\n', 
    new_html, 
    content, 
    flags=re.DOTALL | re.MULTILINE
)

with open("server/app.py", "w", encoding="utf-8") as f:
    f.write(new_content)
