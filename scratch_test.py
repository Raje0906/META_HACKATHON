import asyncio
import threading
import time
import requests
import uvicorn
import httpx
from server.app import app

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="error")

t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(2)

base_url = "http://127.0.0.1:8002"

task_id = "easy_phishing_login"
r = requests.post(f"{base_url}/reset", json={"task_id": task_id})
obs = r.json().get("observation", r.json())

from training.red_vs_blue_loop import epsilon_heuristic_agent
for i in range(5):
    action = epsilon_heuristic_agent(obs, 50)
    print(f"Step {i}: action = {action}")
    sr = requests.post(
        f"{base_url}/step",
        json={"action": {"action_type": action["action_type"], "target": action["target"]}}
    )
    obs = sr.json().get("observation", {})
    
gr = requests.get(f"{base_url}/score")
print(f"Score: {gr.json()}")
