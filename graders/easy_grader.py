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
        actions = state.agent_actions

        ip_blocked = any(
            a.get("action_type") == ActionType.BLOCK_IP.value and a.get("target") == THREAT_IP
            for a in actions
        ) or any(d == f"block:{THREAT_IP}" for d in state.correct_detections)
        user_flagged = any(
            a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == THREAT_USER
            for a in actions
        ) or any(d == f"flag:{THREAT_USER}" for d in state.correct_detections)
        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)

        # ── Primary objectives ────────────────────────────────────────────
        if ip_blocked:
            score += 0.35
        if user_flagged:
            score += 0.35
        if escalated:
            score += 0.10

        # ── False positive penalty ────────────────────────────────────────
        score -= state.false_positives * FP_PENALTY

        # ── Timeliness bonus ──────────────────────────────────────────────
        correct_early = self._check_early_detection(state, threshold_steps=3)
        if correct_early:
            score += 0.10

        score = round(max(0.0, min(MAX_SCORE, score)), 4)
        return score

    def _check_early_detection(self, state: SOCState, threshold_steps: int) -> bool:
        """Return True if the primary threat was acted upon within threshold_steps."""
        for i, action in enumerate(state.agent_actions):
            if i >= threshold_steps:
                break
            if action.get("action_type") == ActionType.BLOCK_IP.value and action.get("target") == THREAT_IP:
                return True
            if action.get("action_type") == ActionType.FLAG_USER.value and action.get("target") == THREAT_USER:
                return True
        return False

    def explain(self, state: SOCState) -> dict:
        """Return a detailed breakdown of the score components."""
        actions = state.agent_actions
        
        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "ip_blocked": any(a.get("action_type") == ActionType.BLOCK_IP.value and a.get("target") == THREAT_IP for a in actions),
            "user_flagged": any(a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == THREAT_USER for a in actions),
            "escalated": any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions),
            "false_positives": state.false_positives,
            "steps_taken": state.step_count,
            "early_detection": self._check_early_detection(state, 3),
            "mitre_tactics": ["T1078 (Valid Accounts)", "T1566 (Phishing)"]
        }
