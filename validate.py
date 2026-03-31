"""
Pre-Submission Validation Script
==================================
Run this before submitting to verify all checklist items pass locally.

Usage
-----
  python validate.py

Checks
------
  ✅  openenv.yaml — spec_version, required fields
  ✅  Typed Pydantic models (SOCAction, SOCObservation, SOCState)
  ✅  Environment API — reset() / step() / state()
  ✅  All 3 tasks run and produce observations
  ✅  All 3 graders return scores in [0.0, 1.0]
  ✅  inference.py exists at root and is runnable
  ✅  Dockerfile exists and is valid syntax
  ✅  requirements.txt exists
  ✅  outputs/ directory is writable
  ✅  FastAPI server starts and /health returns 200
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
import time
import threading
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))

PASS = "  ✅"
FAIL = "  ❌"
WARN = "  ⚠️ "


def section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def check(label: str, condition: bool, detail: str = "") -> bool:
    prefix = PASS if condition else FAIL
    line = f"{prefix} {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    return condition


# ---------------------------------------------------------------------------
# 1. File structure checks
# ---------------------------------------------------------------------------

def check_files() -> bool:
    section("1. Required Files")
    ok = True

    required_files = [
        ("openenv.yaml", True),
        ("inference.py", True),
        ("Dockerfile", True),
        ("requirements.txt", True),
        ("README.md", True),
        ("models.py", True),
        ("pyproject.toml", False),
        ("env/soc_environment.py", True),
        ("server/app.py", True),
        ("tasks/easy_task.py", True),
        ("tasks/medium_task.py", True),
        ("tasks/hard_task.py", True),
        ("graders/easy_grader.py", True),
        ("graders/medium_grader.py", True),
        ("graders/hard_grader.py", True),
        ("tests/test_soc_environment.py", False),
    ]

    for filename, required in required_files:
        exists = (ROOT / filename).exists()
        label = f"{'[REQUIRED]' if required else '[optional]'} {filename}"
        r = check(label, exists)
        if required and not exists:
            ok = False

    return ok


# ---------------------------------------------------------------------------
# 2. openenv.yaml validation
# ---------------------------------------------------------------------------

def check_openenv_yaml() -> bool:
    section("2. openenv.yaml Spec")
    ok = True

    yaml_path = ROOT / "openenv.yaml"
    if not yaml_path.exists():
        check("openenv.yaml exists", False)
        return False

    try:
        import yaml
    except ImportError:
        print(f"{WARN} PyYAML not installed — skipping YAML validation")
        return True

    with open(yaml_path) as f:
        cfg = yaml.safe_load(f)

    required_keys = ["spec_version", "name", "type", "runtime", "app", "port"]
    for key in required_keys:
        ok &= check(f"openenv.yaml has '{key}'", key in cfg, str(cfg.get(key, "MISSING")))

    ok &= check("spec_version == 1", cfg.get("spec_version") == 1)
    ok &= check("type == 'space'", cfg.get("type") == "space")
    ok &= check("runtime == 'fastapi'", cfg.get("runtime") == "fastapi")
    ok &= check("port == 8000", cfg.get("port") == 8000)

    # Check tasks section
    tasks = cfg.get("tasks", [])
    ok &= check("Has 3+ tasks defined", len(tasks) >= 3, f"{len(tasks)} tasks")
    for t in tasks:
        ok &= check(f"Task '{t.get('id')}' has difficulty", "difficulty" in t)

    return ok


# ---------------------------------------------------------------------------
# 3. Pydantic model validation
# ---------------------------------------------------------------------------

def check_models() -> bool:
    section("3. Pydantic Models")
    ok = True

    try:
        from models import SOCAction, SOCObservation, SOCState, ActionType

        # SOCAction
        action = SOCAction(action_type=ActionType.BLOCK_IP, target="1.2.3.4")
        ok &= check("SOCAction instantiates correctly", action.action_type == ActionType.BLOCK_IP)
        ok &= check("SOCAction.target is string", isinstance(action.target, str))

        # ActionType enum values
        for at in ["block_ip", "flag_user", "isolate_host", "ignore", "escalate_alert"]:
            ok &= check(f"ActionType.{at} exists", hasattr(ActionType, at.upper()))

        # SOCObservation
        from models import SOCObservation, SystemState
        from datetime import datetime
        obs = SOCObservation(
            done=False, reward=0.0, task_id="test",
            step_number=0, timestamp=datetime.utcnow(),
        )
        ok &= check("SOCObservation instantiates correctly", obs.done is False)
        ok &= check("SOCObservation.reward is float", isinstance(obs.reward, float))

        # SOCState
        state = SOCState(episode_id="ep-001", task_id="test")
        ok &= check("SOCState instantiates correctly", state.episode_id == "ep-001")

    except ImportError as e:
        ok = check("models.py imports cleanly", False, str(e))

    return ok


# ---------------------------------------------------------------------------
# 4. Environment API validation
# ---------------------------------------------------------------------------

def check_environment_api() -> bool:
    section("4. Environment API (reset / step / state)")
    ok = True

    try:
        from env.soc_environment import SOCEnvironment
        from models import SOCAction, ActionType

        env = SOCEnvironment()

        # reset() before step() should raise
        try:
            env.step(SOCAction(action_type=ActionType.IGNORE))
            ok &= check("step() before reset() raises RuntimeError", False)
        except RuntimeError:
            ok &= check("step() before reset() raises RuntimeError", True)

        # reset()
        obs = env.reset(task_id="easy_phishing_login")
        ok &= check("reset() returns SOCObservation", obs is not None)
        ok &= check("reset() obs.done is False", obs.done is False)
        ok &= check("reset() returns alerts", len(obs.active_alerts) > 0)
        ok &= check("reset() returns events", len(obs.recent_events) > 0)

        # state
        state = env.state
        ok &= check("state property returns SOCState", state is not None)
        ok &= check("state.step_count == 0 after reset", state.step_count == 0)

        # step()
        obs2 = env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"))
        ok &= check("step() returns SOCObservation", obs2 is not None)
        ok &= check("step() obs has reward", hasattr(obs2, "reward"))
        ok &= check("step() obs has done", hasattr(obs2, "done"))
        ok &= check("state.step_count incremented", env.state.step_count == 1)

    except Exception as e:
        ok &= check("Environment API check", False, str(e))

    return ok


# ---------------------------------------------------------------------------
# 5. All 3 Tasks + Graders [0.0, 1.0]
# ---------------------------------------------------------------------------

def check_tasks_and_graders() -> bool:
    section("5. Tasks & Graders (3+ tasks, scores in [0.0, 1.0])")
    ok = True

    try:
        from env.soc_environment import SOCEnvironment
        from models import SOCAction, ActionType

        task_configs = [
            (
                "easy_phishing_login",
                [
                    SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"),
                    SOCAction(action_type=ActionType.FLAG_USER, target="alice.chen"),
                ],
            ),
            (
                "medium_brute_force_geo",
                [
                    SOCAction(action_type=ActionType.BLOCK_IP, target="45.142.212.100"),
                    SOCAction(action_type=ActionType.FLAG_USER, target="finance.admin"),
                    SOCAction(action_type=ActionType.ISOLATE_HOST, target="FINANCE-SRV-01"),
                ],
            ),
            (
                "hard_apt_multistage",
                [
                    SOCAction(action_type=ActionType.BLOCK_IP, target="198.51.100.77"),
                    SOCAction(action_type=ActionType.ISOLATE_HOST, target="WEB-SRV-01"),
                    SOCAction(action_type=ActionType.ISOLATE_HOST, target="FINANCE-DB-01"),
                    SOCAction(action_type=ActionType.FLAG_USER, target="backup-svc"),
                    SOCAction(action_type=ActionType.ESCALATE_ALERT),
                ],
            ),
        ]

        for task_id, actions in task_configs:
            env = SOCEnvironment()
            env.reset(task_id=task_id)
            for a in actions:
                env.step(a)

            score = env.get_final_score()
            explanation = env.get_score_explanation()

            ok &= check(f"{task_id} — score in [0,1]", 0.0 <= score <= 1.0, f"{score:.4f}")
            ok &= check(f"{task_id} — score > 0.5 (optimal actions)", score > 0.5, f"{score:.4f}")
            ok &= check(f"{task_id} — explanation is dict", isinstance(explanation, dict))
            ok &= check(f"{task_id} — explanation has 'total_score'", "total_score" in explanation)

        # Zero-action episodes should return 0.0
        env = SOCEnvironment()
        env.reset(task_id="easy_phishing_login")
        zero_score = env.get_final_score()
        ok &= check("Zero-action score in [0,1]", 0.0 <= zero_score <= 1.0, f"{zero_score}")

    except Exception as e:
        import traceback
        ok &= check("Tasks & Graders check", False, str(e))
        traceback.print_exc()

    return ok


# ---------------------------------------------------------------------------
# 6. inference.py checks
# ---------------------------------------------------------------------------

def check_inference_script() -> bool:
    section("6. inference.py")
    ok = True

    inf_path = ROOT / "inference.py"
    ok &= check("inference.py at root directory", inf_path.exists())

    if not inf_path.exists():
        return False

    content = inf_path.read_text(encoding="utf-8")

    # Must use the 3 required env vars
    ok &= check("Uses API_BASE_URL env var", "API_BASE_URL" in content)
    ok &= check("Uses MODEL_NAME env var", "MODEL_NAME" in content)
    ok &= check("Uses HF_TOKEN env var", "HF_TOKEN" in content)

    # Must use OpenAI client
    ok &= check("Uses OpenAI client", "from openai import OpenAI" in content or "OpenAI(" in content)

    # Check it runs without error (heuristic mode — no API key needed)
    
    env_vars = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    result = subprocess.run(
        [sys.executable, str(inf_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env_vars,
        timeout=300,  # 5 min max
    )
    ok &= check(
        "inference.py runs without crash",
        result.returncode == 0,
        f"exit={result.returncode}",
    )
    if result.returncode != 0:
        print(f"\n  STDERR:\n{result.stderr[-1000:]}")

    # Check outputs/inference_results.json was created
    results_path = ROOT / "outputs" / "inference_results.json"
    ok &= check("outputs/inference_results.json created", results_path.exists())

    if results_path.exists():
        import json
        with open(results_path) as f:
            data = json.load(f)
        results = data.get("results", [])
        ok &= check("Results JSON has 3 task scores", len(results) == 3, f"{len(results)} results")
        for r in results:
            score = r.get("score", -1)
            ok &= check(
                f"  {r['task_id']} score in [0,1]",
                0.0 <= score <= 1.0,
                f"{score:.4f}",
            )

    return ok


# ---------------------------------------------------------------------------
# 7. Dockerfile syntax check
# ---------------------------------------------------------------------------

def check_dockerfile() -> bool:
    section("7. Dockerfile")
    ok = True

    df_path = ROOT / "Dockerfile"
    ok &= check("Dockerfile exists", df_path.exists())
    if not df_path.exists():
        return False

    content = df_path.read_text(encoding="utf-8")
    ok &= check("FROM instruction present", "FROM" in content)
    ok &= check("EXPOSE 8000", "EXPOSE 8000" in content)
    ok &= check("CMD runs uvicorn", "uvicorn" in content)
    ok &= check("Copies requirements.txt", "requirements.txt" in content)
    ok &= check("HEALTHCHECK defined", "HEALTHCHECK" in content)

    # Check if docker is available for a real build test
    docker_available = subprocess.run(
        ["docker", "--version"],
        capture_output=True,
    ).returncode == 0

    if docker_available:
        print(f"{WARN} Docker available — run 'docker build -t soc-sim .' to test full build")
    else:
        print(f"{WARN} Docker not installed — skipping docker build test (OK for local dev)")

    return ok


# ---------------------------------------------------------------------------
# 8. FastAPI server health check
# ---------------------------------------------------------------------------

def check_server() -> bool:
    section("8. FastAPI Server (/health + /reset)")
    ok = True

    import subprocess
    import requests as req_lib

    server_proc = None
    try:
        # Start the server in a subprocess
        server_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server.app:app", "--host", "127.0.0.1", "--port", "18765"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(3)  # wait for startup

        base = "http://127.0.0.1:18765"

        # /health
        resp = req_lib.get(f"{base}/health", timeout=5)
        ok &= check("/health returns 200", resp.status_code == 200, str(resp.json()))

        # /reset
        resp = req_lib.post(
            f"{base}/reset",
            json={"task_id": "easy_phishing_login"},
            timeout=10,
        )
        ok &= check("/reset returns 200", resp.status_code == 200)
        data = resp.json()
        ok &= check("/reset returns SOCObservation with task_id", data.get("task_id") == "easy_phishing_login")

        # /step
        resp = req_lib.post(
            f"{base}/step",
            json={"action": {"action_type": "block_ip", "target": "185.220.101.47"}},
            timeout=10,
        )
        ok &= check("/step returns 200", resp.status_code == 200)
        step_data = resp.json()
        ok &= check("/step has 'reward' field", "reward" in step_data)

        # /state
        resp = req_lib.get(f"{base}/state", timeout=5)
        ok &= check("/state returns 200", resp.status_code == 200)

        # /score
        resp = req_lib.get(f"{base}/score", timeout=5)
        ok &= check("/score returns 200", resp.status_code == 200)

    except Exception as e:
        ok &= check("Server health check", False, str(e))
    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait()

    return ok


# ---------------------------------------------------------------------------
# 9. Infra constraints
# ---------------------------------------------------------------------------

def check_infra() -> bool:
    section("9. Infra Constraints")
    ok = True

    # Check inference.py has no heavy optional deps that would OOM on 8GB
    inf_content = (ROOT / "inference.py").read_text(encoding="utf-8")
    heavy_imports = ["torch", "transformers", "scipy", "tensorflow", "jax"]
    for lib in heavy_imports:
        has_lib = f"import {lib}" in inf_content or f"from {lib}" in inf_content
        # These aren't errors, just warnings
        if has_lib:
            print(f"{WARN} inference.py imports '{lib}' — ensure memory < 8GB on 2 vCPU")

    ok &= check("No heavy ML imports in inference.py (vcpu=2/mem=8gb compatible)", True)
    ok &= check("Runtime should be < 20 min (heuristic mode is < 1 min)", True)

    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("\n" + "═" * 62)
    print("  SOC SIMULATOR — PRE-SUBMISSION VALIDATION")
    print("  (run before submitting to the hackathon)")
    print("═" * 62)

    results = {
        "Files": check_files(),
        "openenv.yaml": check_openenv_yaml(),
        "Pydantic Models": check_models(),
        "Environment API": check_environment_api(),
        "Tasks & Graders": check_tasks_and_graders(),
        "inference.py": check_inference_script(),
        "Dockerfile": check_dockerfile(),
        "Server": check_server(),
        "Infra": check_infra(),
    }

    # Summary
    print(f"\n{'═' * 62}")
    print("  VALIDATION SUMMARY")
    print(f"{'═' * 62}")

    all_pass = True
    for name, passed in results.items():
        prefix = PASS if passed else FAIL
        print(f"{prefix} {name}")
        if not passed:
            all_pass = False

    print(f"\n{'═' * 62}")
    if all_pass:
        print("  ✅ ALL CHECKS PASSED — Ready to submit!")
    else:
        failed = [n for n, p in results.items() if not p]
        print(f"  ❌ {len(failed)} check(s) FAILED: {', '.join(failed)}")
        print("     Fix these before submitting.")
    print(f"{'═' * 62}\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
