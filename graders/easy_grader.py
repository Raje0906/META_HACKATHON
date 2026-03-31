"""
EASY TASK GRADER
=================
Evaluates agent performance on the phishing + malicious-login scenario.

Scoring Rubric (total: 1.0)
────────────────────────────
• IP blocked (185.220.101.47)         → +0.35
• User flagged (alice.chen)           → +0.35
• Alert acknowledged (escalate)       → +0.10
• No false positives                  → +0.20  (deducted by FP count)
• Timeliness bonus (<= 3 steps)       → +0.10  (bonus on top, capped at 1.0)
"""

from __future__ import annotations

from typing import List

from models import ActionType, SOCAction, SOCState


THREAT_IP = "185.220.101.47"
THREAT_USER = "alice.chen"
MAX_SCORE = 1.0
FP_PENALTY = 0.10   # per false positive action


class EasyGrader:
    """
    Deterministic grader for the EASY phishing/login task.

    Args
    ----
    state: Final SOCState after episode completion.

    Returns
    -------
    float in [0.0, 1.0]
    """

    TASK_ID = "easy_phishing_login"

    def grade(self, state: SOCState) -> float:
        """Compute and return a normalised score [0, 1]."""
        score = 0.0

        actions = state.agent_actions  # list of action dicts

        # Collect unique action types and targets using robust ENUM value parsing
        block_ips = {
            a["target"] for a in actions if a["action_type"] == ActionType.BLOCK_IP.value
        }
        flagged_users = {
            a["target"] for a in actions if a["action_type"] == ActionType.FLAG_USER.value
        }
        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)

        # ── Primary objectives ────────────────────────────────────────────
        if THREAT_IP in block_ips:
            score += 0.35

        if THREAT_USER in flagged_users:
            score += 0.35

        if escalated:
            score += 0.10

        # ── False positive penalty ────────────────────────────────────────
        false_positive_blocks = {ip for ip in block_ips if ip != THREAT_IP}
        false_positive_flags = {u for u in flagged_users if u != THREAT_USER}
        fp_count = len(false_positive_blocks) + len(false_positive_flags)
        score -= fp_count * FP_PENALTY

        # ── Timeliness bonus ──────────────────────────────────────────────
        # Award bonus if correct actions taken within 3 steps
        correct_early = self._check_early_detection(actions, threshold_steps=3)
        if correct_early:
            score += 0.10

        # Clamp to [0, 1]
        score = round(max(0.0, min(MAX_SCORE, score)), 4)
        return score

    def _check_early_detection(self, actions: list, threshold_steps: int) -> bool:
        """Return True if the primary threat was acted upon within threshold_steps."""
        ip_blocked_early = False
        user_flagged_early = False

        for i, action in enumerate(actions):
            if i >= threshold_steps:
                break
            if action["action_type"] == ActionType.BLOCK_IP.value and action["target"] == THREAT_IP:
                ip_blocked_early = True
            if action["action_type"] == ActionType.FLAG_USER.value and action["target"] == THREAT_USER:
                user_flagged_early = True

        return ip_blocked_early or user_flagged_early

    def explain(self, state: SOCState) -> dict:
        """Return a detailed breakdown of the score components."""
        actions = state.agent_actions
        block_ips = {a["target"] for a in actions if a["action_type"] == ActionType.BLOCK_IP.value}
        flagged_users = {a["target"] for a in actions if a["action_type"] == ActionType.FLAG_USER.value}

        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "ip_blocked": THREAT_IP in block_ips,
            "user_flagged": THREAT_USER in flagged_users,
            "escalated": any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions),
            "false_positives": state.false_positives,
            "steps_taken": state.step_count,
            "early_detection": self._check_early_detection(actions, 3),
        }
