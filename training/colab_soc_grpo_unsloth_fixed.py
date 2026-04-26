"""
SOC Simulator — GRPO on Colab (Unsloth + TRL), fixed for text-only Llama models
==============================================================================

Fixes the Colab crash:
    AttributeError: 'UnslothGRPOTrainer' object has no attribute 'image_token_id'

Cause: Unsloth's patched GRPO trainer sometimes expects multimodal (VL) token ids;
       plain Llama checkpoints do not define them on the trainer.

Usage in Google Colab
---------------------
1) **New runtime** (recommended after pip churn).

2) Install (pick ONE path — pinned stack is more stable on T4):

   Option A — Unsloth install script (often easiest on Colab):
   ```
   !pip install -U "pip" "packaging"
   !pip install -U "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
   !pip install -U "trl" "datasets" "requests" "wandb"
   ```

   Option B — If you still see trainer / trl mismatches, wipe Unsloth cache then reinstall:
   ```
   !rm -rf /content/unsloth_compiled_cache
   !pip install -U --force-reinstall "unsloth" "unsloth_zoo" "trl" "transformers" "accelerate"
   ```

3) Paste this entire file into a cell **OR** upload it and `%run colab_soc_grpo_unsloth_fixed.py`

4) Set secrets via Colab secrets / env vars — **never** hard‑paste API keys in the notebook:
   - `WANDB_API_KEY`
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import random
import re
import time
from typing import Any, Dict, List, Optional

import requests
import torch
from datasets import Dataset

# Unsloth must patch TRL *before* you construct GRPOTrainer (recommended by Unsloth GRPO docs).
from unsloth import FastLanguageModel, PatchFastRL, is_bfloat16_supported

PatchFastRL("GRPO", FastLanguageModel)

from trl import GRPOConfig, GRPOTrainer

# ---------------------------------------------------------------------------
# 1) Configuration
# ---------------------------------------------------------------------------

API_URL = os.environ.get("SOC_API_URL", "https://aditya9605-meta-hackathon-finale.hf.space")
# Unsloth-optimized id avoids some hub template edge cases; meta-llama also works if you accept gating.
MODEL_ID = os.environ.get("SOC_MODEL_ID", "unsloth/Llama-3.2-3B-Instruct")

os.environ.setdefault("WANDB_PROJECT", "soc-simulator-grpo")
os.environ.setdefault("WANDB_SILENT", "true")

NUM_SCENARIOS = 80
MAX_STEPS = 150
LEARNING_RATE = 5e-6
NUM_GENERATIONS = 4
MAX_COMPLETION_LENGTH = 96
SEED = 3407

random.seed(SEED)

TASK_MIX = (
    ["easy_phishing_login"] * 30
    + ["medium_brute_force_geo"] * 30
    + ["hard_apt_multistage"] * 40
)

VALID_ACTIONS = {"block_ip", "flag_user", "isolate_host", "escalate_alert", "ignore"}


def resolve_wandb_report_to() -> str:
    if os.environ.get("WANDB_API_KEY", "").strip():
        return "wandb"
    try:
        from google.colab import userdata
    except ImportError:
        print("WANDB_API_KEY not set; using report_to=none.")
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
    print("No W&B key; report_to=none (training continues without W&B).")
    return "none"


def patch_unsloth_text_only_grpo_trainer(trainer: Any) -> None:
    """
    UnslothGRPOTrainer may reference VL-only attributes. For text-only models, set to None.
    Call immediately after GRPOTrainer(...) construction.
    """
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
        "Your job is to inspect logs and alerts and return exactly one action.\n\n"
        "VALID ACTIONS:\n"
        "- block_ip (target: IP)\n"
        "- flag_user (target: username)\n"
        "- isolate_host (target: hostname)\n"
        "- escalate_alert (target: system)\n"
        "- ignore (target: system)\n\n"
        "RESPONSE FORMAT (strict):\n"
        '<action>{"action_type":"block_ip","target":"198.51.100.77","reason":"..."}</action>\n\n'
        f"--- RECENT EVENTS ---\n{json.dumps(events[:6], indent=2)}\n\n"
        f"--- ACTIVE ALERTS ---\n{json.dumps(alerts[:3], indent=2)}\n\n"
        "Return only the XML-tagged JSON action."
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


ACTION_RE = re.compile(r"<action>(.*?)</action>", re.DOTALL)
TASK_RE = re.compile(r"TASK_CONTEXT:\s*([a-zA-Z0-9_]+)")


def extract_json_action(text: str) -> Optional[dict]:
    m = ACTION_RE.search(text or "")
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        obj = json.loads(raw)
        at = obj.get("action_type")
        if at not in VALID_ACTIONS:
            return None
        if at in {"ignore", "escalate_alert"}:
            obj["target"] = "system"
        return obj
    except Exception:
        return None


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


def format_reward_func(completions, **kwargs) -> List[float]:
    rewards: List[float] = []
    for completion in completions:
        text = completion[0]["content"] if completion and completion[0] else ""
        action = extract_json_action(text)
        if action is None:
            rewards.append(-1.0)
        else:
            reason = str(action.get("reason", "") or "")
            length_pen = -0.05 if len(reason) > 180 else 0.0
            rewards.append(0.45 + length_pen)
    return rewards


def environment_reward_func(
    completions,
    prompts=None,
    task_id=None,
    **kwargs,
) -> List[float]:
    prompts = prompts or []
    task_id_col = task_id or []

    def one_item(i: int) -> float:
        completion = completions[i]
        text = completion[0]["content"] if completion and completion[0] else ""
        action = extract_json_action(text)
        if action is None:
            return -0.6

        tid: Optional[str] = None
        if i < len(task_id_col):
            tid = task_id_col[i]
        if not tid:
            prompt_item = prompts[i] if i < len(prompts) else None
            tid = extract_task_id_from_prompt(prompt_item)

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
    warmup_space(API_URL)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_ID,
        max_seq_length=2048,
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
        gradient_accumulation_steps=8,
        max_steps=MAX_STEPS,
        save_steps=25,
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
    trainer.train()

    save_path = "models/soc_simulator_grpo_final"
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)
    print(f"Training complete. Saved adapter to: {save_path}")


if __name__ == "__main__":
    main()
