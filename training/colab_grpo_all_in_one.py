# =============================================================================
# SOC Simulator — Colab GRPO (Unsloth + TRL) — ALL IN ONE
# =============================================================================
#
# Copy this entire file into ONE Colab code cell, OR upload and run:
#   %run colab_grpo_all_in_one.py
#
# --- CELL 0 (recommended): install — run once, then Runtime → Restart session ---
# !pip install -U pip packaging
# !pip install -U "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
# Pin TRL + datasets to versions that match your Unsloth build (avoids surprise upgrades):
# !pip install -U "requests" "wandb" "accelerate" "peft" "bitsandbytes" "trl==0.23.0" "datasets==4.3.0"
# (Alternative: unpinned trl/datasets — only if you know they match your Unsloth release.)
#
# If you see weird Unsloth/TRL compile errors, clear cache and reinstall:
# !rm -rf /content/unsloth_compiled_cache
#
# --- Secrets (Colab: Secrets sidebar) ---
#   Name MUST match what the code looks up (default: WANDB_API_KEY).
#   Turn ON "Notebook access" for that secret.
#   This script loads it via: google.colab.userdata.get("WANDB_API_KEY")
#   If the secret name is wrong or access is off, you get:
#       UsageError: No API key configured. Use `wandb login` to log in.
#   SOC_API_URL     — optional override for your HF Space
#   SOC_MODEL_ID    — optional, default unsloth/Llama-3.2-3B-Instruct
#   SOC_MAX_SEQ_LENGTH     — default 1024 (fast); raise to 2048 for higher quality
#   SOC_MAX_COMPLETION_LENGTH — default 192 (fast); raise to 256 if clipping too much
#   SOC_NUM_SCENARIOS / SOC_MAX_STEPS / SOC_NUM_GENERATIONS / SOC_GRAD_ACC_STEPS
#     Use these to trade speed vs quality without editing code.
#
# --- Optional: auto-pip from this script (set env then run) ---
#   os.environ["SOC_COLAB_AUTO_PIP"] = "1"
# =============================================================================

from __future__ import annotations

import concurrent.futures
import json
import os
import random
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional one-click pip (Colab only, guarded by SOC_COLAB_AUTO_PIP=1)
# ---------------------------------------------------------------------------


def _maybe_auto_pip() -> None:
    if os.environ.get("SOC_COLAB_AUTO_PIP", "").strip() != "1":
        return
    try:
        import google.colab  # noqa: F401
    except ImportError:
        print("SOC_COLAB_AUTO_PIP=1 but not on Colab; skipping pip.")
        return
    cmds = [
        [sys.executable, "-m", "pip", "install", "-U", "pip", "packaging"],
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-U",
            "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git",
        ],
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-U",
            "requests",
            "wandb",
            "accelerate",
            "peft",
            "bitsandbytes",
            "trl==0.23.0",
            "datasets==4.3.0",
        ],
    ]
    for argv in cmds:
        print("+", " ".join(argv))
        subprocess.check_call(argv)
    print("Auto-pip done. Prefer: Runtime → Restart session, then re-run without SOC_COLAB_AUTO_PIP.")


_maybe_auto_pip()

import requests
import torch
from datasets import Dataset

# Unsloth patches TRL before GRPOTrainer is constructed.
from unsloth import FastLanguageModel, PatchFastRL, is_bfloat16_supported

PatchFastRL("GRPO", FastLanguageModel)

from trl import GRPOConfig, GRPOTrainer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("SOC_API_URL", "https://aditya9605-meta-hackathon-finale.hf.space")
MODEL_ID = os.environ.get("SOC_MODEL_ID", "unsloth/Llama-3.2-3B-Instruct")

os.environ.setdefault("WANDB_PROJECT", "soc-simulator-grpo")
os.environ.setdefault("WANDB_SILENT", "true")

# Fast-run defaults (lower wall-clock on Colab T4). Override via env vars when needed.
NUM_SCENARIOS = int(os.environ.get("SOC_NUM_SCENARIOS", "40"))
MAX_STEPS = int(os.environ.get("SOC_MAX_STEPS", "40"))
LEARNING_RATE = float(os.environ.get("SOC_LEARNING_RATE", "5e-6"))
NUM_GENERATIONS = int(os.environ.get("SOC_NUM_GENERATIONS", "2"))
# Keep enough room for structured <action> JSON while remaining faster than 256.
MAX_COMPLETION_LENGTH = int(os.environ.get("SOC_MAX_COMPLETION_LENGTH", "192"))
MAX_SEQ_LENGTH = int(os.environ.get("SOC_MAX_SEQ_LENGTH", "1024"))
GRADIENT_ACCUMULATION_STEPS = int(os.environ.get("SOC_GRAD_ACC_STEPS", "4"))
SAVE_STEPS = int(os.environ.get("SOC_SAVE_STEPS", "20"))
SEED = 3407

random.seed(SEED)

TASK_MIX = (
    ["easy_phishing_login"] * 12
    + ["medium_brute_force_geo"] * 12
    + ["hard_apt_multistage"] * 16
)

VALID_ACTIONS = {"block_ip", "flag_user", "isolate_host", "escalate_alert", "ignore"}


def resolve_wandb_report_to() -> str:
    """
    HF Trainer + W&B need an API key on Colab (no interactive login).
    Try env first, then Colab Secrets. If still missing, disable W&B so training runs.
    """
    if os.environ.get("WANDB_API_KEY", "").strip():
        return "wandb"

    try:
        from google.colab import userdata
    except ImportError:
        print("WANDB_API_KEY not set and not on Colab; using report_to=none.")
        return "none"

    for secret_name in ("WANDB_API_KEY", "WANDB_KEY", "wandb_api_key"):
        try:
            val = userdata.get(secret_name)
        except Exception:
            continue
        if val and str(val).strip():
            os.environ["WANDB_API_KEY"] = str(val).strip()
            print(f"Using W&B API key from Colab Secret: {secret_name!r}")
            return "wandb"

    print(
        "No W&B API key found. Add a Colab Secret named WANDB_API_KEY "
        "(enable Notebook access), or set os.environ['WANDB_API_KEY']. "
        "Training will continue with report_to=none."
    )
    return "none"


def wandb_login_noninteractive(report_to: str) -> None:
    """Call wandb.login(key=...) when key is in env — avoids UsageError on headless Colab."""
    if report_to != "wandb":
        return
    key = os.environ.get("WANDB_API_KEY", "").strip()
    if not key:
        return
    try:
        import wandb
    except ImportError:
        print("wandb not installed; skipping wandb.login.")
        return
    wandb.login(key=key, relogin=True)


def patch_unsloth_text_only_grpo_trainer(trainer: Any) -> None:
    """Fix: AttributeError 'UnslothGRPOTrainer' has no attribute 'image_token_id' on text LMs."""
    for name in ("image_token_id", "vision_start_token_id", "vision_end_token_id"):
        if not hasattr(trainer, name):
            setattr(trainer, name, None)


def warmup_space(url: str, timeout_s: int = 90) -> None:
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            r = requests.get(f"{url}/health", timeout=8)
            if r.status_code == 200:
                print("HF Space ready.")
                return
        except Exception:
            pass
        time.sleep(2)
    print("Warning: Space warmup timeout, continuing anyway.")


def build_soc_prompt(events: list, alerts: list, task_id: str) -> str:
    return (
        "You are an autonomous Tier-2 SOC Analyst.\n"
        f"TASK_CONTEXT: {task_id}\n\n"
        "Inspect logs and alerts. Reply with EXACTLY ONE line in this format (double quotes inside JSON):\n"
        '<action>{"action_type":"block_ip","target":"198.51.100.77","reason":"brief"}</action>\n\n'
        "No markdown fences, no extra commentary before or after the <action> block.\n\n"
        "VALID action_type values:\n"
        "block_ip | flag_user | isolate_host | escalate_alert | ignore\n"
        "For escalate_alert and ignore, set target to the string system.\n\n"
        f"--- RECENT EVENTS ---\n{json.dumps(events[:6], indent=2)}\n\n"
        f"--- ACTIVE ALERTS ---\n{json.dumps(alerts[:3], indent=2)}\n\n"
        "Your <action> line:"
    )


def fetch_one_scenario(task_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.post(
            f"{API_URL}/reset",
            json={
                "task_id": task_id,
                "custom_params": {
                    "enable_schema_drift": True,
                    "enable_red_agent": True,
                    "use_live_threat_intel": True,
                },
            },
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        obs = resp.json().get("observation", resp.json())
        events = obs.get("recent_events", [])
        alerts = obs.get("active_alerts", [])
        prompt_text = build_soc_prompt(events, alerts, task_id)
        messages = [
            {"role": "system", "content": "You are a senior cybersecurity incident responder."},
            {"role": "user", "content": prompt_text},
        ]
        return {"prompt": messages, "task_id": task_id}
    except Exception:
        return None


def generate_training_dataset(num_scenarios: int = 80) -> Dataset:
    print(f"Fetching {num_scenarios} scenarios from {API_URL} ...")
    tasks = list(TASK_MIX)
    random.shuffle(tasks)
    rows: List[Dict[str, Any]] = []
    for t in tasks:
        if len(rows) >= num_scenarios:
            break
        row = fetch_one_scenario(t)
        if row is not None:
            rows.append(row)
    if len(rows) < 20:
        raise RuntimeError(f"Only fetched {len(rows)} scenarios. Check Space/API stability.")
    print(f"Collected {len(rows)} scenarios.")
    return Dataset.from_list(rows)


ACTION_RE = re.compile(r"<action>\s*(.*?)\s*</action>", re.DOTALL | re.IGNORECASE)
TASK_RE = re.compile(r"TASK_CONTEXT:\s*([a-zA-Z0-9_]+)")
FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def _normalize_action_dict(obj: Any) -> Optional[dict]:
    if not isinstance(obj, dict):
        return None
    at = obj.get("action_type") or obj.get("action") or obj.get("type")
    if isinstance(at, str):
        at = at.strip()
    if at not in VALID_ACTIONS:
        return None
    tgt = obj.get("target")
    if tgt is not None and not isinstance(tgt, str):
        tgt = str(tgt)
    if at in {"ignore", "escalate_alert"}:
        tgt = "system"
    if not tgt or not str(tgt).strip():
        return None
    out = {
        "action_type": at,
        "target": str(tgt).strip(),
        "reason": obj.get("reason"),
        "confidence": obj.get("confidence", 1.0),
    }
    return out


def _json_loads_lenient(raw: str) -> Optional[dict]:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        val = json.loads(raw)
        return val if isinstance(val, dict) else None
    except json.JSONDecodeError:
        pass
    try:
        val = json.loads(raw.replace("'", '"'))
        return val if isinstance(val, dict) else None
    except Exception:
        return None


def _yield_json_dicts(text: str):
    """Scan for top-level JSON objects via raw_decode (handles trailing junk)."""
    decoder = json.JSONDecoder()
    s = str(text or "")
    i = 0
    n = len(s)
    while i < n:
        if s[i] != "{":
            i += 1
            continue
        try:
            obj, end = decoder.raw_decode(s, i)
            if isinstance(obj, dict):
                yield obj
            i = end
        except json.JSONDecodeError:
            i += 1


def extract_json_action(text: str) -> Optional[dict]:
    """
    Parse model output into an API-ready action dict.
    Accepts strict <action>...</action>, markdown ```json``` fences, or a bare JSON object.
    """
    t = str(text or "").strip()
    if not t:
        return None

    m = ACTION_RE.search(t)
    if m:
        inner = m.group(1).strip()
        obj = _json_loads_lenient(inner)
        norm = _normalize_action_dict(obj) if obj else None
        if norm:
            return norm

    fm = FENCE_RE.search(t)
    if fm:
        obj = _json_loads_lenient(fm.group(1))
        norm = _normalize_action_dict(obj) if obj else None
        if norm:
            return norm

    for obj in _yield_json_dicts(t):
        norm = _normalize_action_dict(obj)
        if norm:
            return norm

    return None


def format_parse_soft_score(text: str) -> float:
    """
    Shaped signal when strict parse fails (reduces flat -1.0 plateaus in GRPO).
    Returns in [-0.35, 0.15].
    """
    t = (text or "").lower()
    if "<action>" in t and "</action>" in t:
        return 0.05
    if "```json" in t or "```" in t:
        return 0.0
    if any(k in t for k in ("action_type", "block_ip", "flag_user", "isolate_host")):
        return -0.15
    return -0.35


def extract_task_id_from_prompt(prompt_item: Any, fallback: str = "hard_apt_multistage") -> str:
    try:
        if isinstance(prompt_item, list):
            for msg in prompt_item:
                if isinstance(msg, dict) and msg.get("role") == "user":
                    txt = msg.get("content", "")
                    m = TASK_RE.search(txt)
                    if m:
                        return m.group(1)
        elif isinstance(prompt_item, str):
            m = TASK_RE.search(prompt_item)
            if m:
                return m.group(1)
    except Exception:
        pass
    return fallback


def _resolve_task_id_for_index(
    i: int,
    prompts: List[Any],
    task_id_kw: Any,
    reward_kwargs: Dict[str, Any],
) -> str:
    """TRL may pass task column as task_id=..., or inside inputs=...; be defensive."""
    col = task_id_kw
    if col is None:
        col = reward_kwargs.get("task_id")
    if isinstance(col, list) and i < len(col) and col[i]:
        return str(col[i])
    if isinstance(col, str) and col:
        return col
    inputs = reward_kwargs.get("inputs")
    if isinstance(inputs, list) and i < len(inputs):
        row = inputs[i]
        if isinstance(row, dict) and row.get("task_id"):
            return str(row["task_id"])
    prompt_item = prompts[i] if i < len(prompts) else None
    return extract_task_id_from_prompt(prompt_item)


def format_reward_func(completions, **kwargs) -> List[float]:
    rewards: List[float] = []
    for completion in completions:
        text = completion[0]["content"] if completion and completion[0] else ""
        action = extract_json_action(text)
        if action is not None:
            reason = str(action.get("reason", "") or "")
            length_pen = -0.05 if len(reason) > 180 else 0.0
            rewards.append(0.55 + length_pen)
        else:
            rewards.append(-0.65 + format_parse_soft_score(text))
    return rewards


def environment_reward_func(
    completions,
    prompts=None,
    task_id=None,
    **kwargs,
) -> List[float]:
    prompts = prompts or []

    def one_item(i: int) -> float:
        completion = completions[i]
        text = completion[0]["content"] if completion and completion[0] else ""
        action = extract_json_action(text)
        if action is None:
            return -0.6

        tid = _resolve_task_id_for_index(i, prompts, task_id, kwargs)

        try:
            rr = requests.post(
                f"{API_URL}/reset",
                json={
                    "task_id": tid,
                    "custom_params": {
                        "enable_schema_drift": True,
                        "enable_red_agent": True,
                        "use_live_threat_intel": True,
                    },
                },
                timeout=8,
            )
            if rr.status_code != 200:
                return -0.4

            sr = requests.post(f"{API_URL}/step", json={"action": action}, timeout=8)
            if sr.status_code != 200:
                return -0.4

            step_data = sr.json()
            step_reward = float(step_data.get("reward", 0.0))

            gr = requests.get(f"{API_URL}/score", timeout=8)
            final_score = float(gr.json().get("score", 0.0)) if gr.status_code == 200 else 0.0

            return (0.7 * step_reward) + (0.3 * final_score)
        except Exception:
            return -0.2

    workers = min(8, max(1, len(completions)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(one_item, range(len(completions))))


def main() -> None:
    print("Initializing GRPO pipeline...")
    report_to = resolve_wandb_report_to()
    wandb_login_noninteractive(report_to)
    warmup_space(API_URL)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_ID,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=torch.bfloat16 if is_bfloat16_supported() else torch.float16,
        load_in_4bit=True,
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=32,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_alpha=32,
        use_gradient_checkpointing="unsloth",
        random_state=SEED,
    )

    dataset = generate_training_dataset(NUM_SCENARIOS)

    args = GRPOConfig(
        output_dir="outputs/soc_grpo_production",
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
        max_steps=MAX_STEPS,
        save_steps=SAVE_STEPS,
        logging_steps=5,
        num_generations=NUM_GENERATIONS,
        max_completion_length=MAX_COMPLETION_LENGTH,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        optim="adamw_8bit",
        report_to=report_to,
        seed=SEED,
    )

    trainer = GRPOTrainer(
        model=model,
        processing_class=tokenizer,
        reward_funcs=[format_reward_func, environment_reward_func],
        args=args,
        train_dataset=dataset,
    )

    patch_unsloth_text_only_grpo_trainer(trainer)

    print("Starting GRPO training...")
    # To continue from checkpoint after interruption:
    # trainer.train(resume_from_checkpoint=True)
    trainer.train()

    save_path = "models/soc_simulator_grpo_final"
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)
    print(f"Training complete. Saved adapter to: {save_path}")


if __name__ == "__main__":
    main()
