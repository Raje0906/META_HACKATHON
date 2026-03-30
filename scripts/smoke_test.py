"""Quick smoke test for the validator's 3 HTTP checks."""
import sys
sys.path.insert(0, ".")
from server.app import app
from fastapi.testclient import TestClient

client = TestClient(app)

# Validator Step 1: POST /reset with EMPTY body {}
r = client.post("/reset", json={})
assert r.status_code == 200, f"FAIL /reset empty body: {r.status_code} {r.text}"
assert r.json().get("task_id") == "easy_phishing_login"
print(f"OK  POST /reset {{}}  -> 200  task_id={r.json()['task_id']}")

# /reset with explicit task
r = client.post("/reset", json={"task_id": "hard_apt_multistage"})
assert r.status_code == 200
print(f"OK  POST /reset hard -> 200  task_id={r.json()['task_id']}")

# /health
r = client.get("/health")
assert r.status_code == 200
print(f"OK  GET  /health     -> 200  {r.json()}")

# /step
r = client.post("/reset", json={})
r = client.post("/step", json={"action": {"action_type": "block_ip", "target": "185.220.101.47"}})
assert r.status_code == 200
print(f"OK  POST /step       -> 200  reward={r.json()['reward']}")

# /state
r = client.get("/state")
assert r.status_code == 200
print(f"OK  GET  /state      -> 200  step_count={r.json()['step_count']}")

# /score
r = client.get("/score")
assert r.status_code == 200
assert 0.0 <= r.json()["score"] <= 1.0
print(f"OK  GET  /score      -> 200  score={r.json()['score']}")

print("\nAll HTTP endpoint checks PASSED")
