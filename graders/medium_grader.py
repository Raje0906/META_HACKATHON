"""
MEDIUM TASK GRADER
==================
Evaluates agent performance on the brute-force / geo-anomaly scenario.

Scoring Rubric (total: 1.0)
────────────────────────────
• Primary attacker IP blocked (45.142.212.100)   → +0.30
• Secondary attacker IP blocked (91.108.56.22)   → +0.15
• Compromised user flagged (finance.admin)        → +0.25
• Affected host isolated (FINANCE-SRV-01)         → +0.15
• No false positives                              → +0.15  (deducted per FP)
• Timeliness (correct action within 4 steps)      → +0.10  (bonus, capped 1.0)
"""

from __future__ import annotations

from models import ActionType, SOCState


PRIMARY_IP = "45.142.212.100"
SECONDARY_IP = "91.108.56.22"
BENIGN_IP = "77.88.55.88"  # Red herring — flagging this is a false positive
THREAT_USER = "finance.admin"
THREAT_HOST = "FINANCE-SRV-01"
FP_PENALTY = 0.08


class MediumGrader:
    """Deterministic grader for the MEDIUM brute-force task."""

    TASK_ID = "medium_brute_force_geo"

    def grade(self, state: SOCState) -> float:
        actions = state.agent_actions
        score = 0.0

        blocked_targets = {
            a.get("target")
            for a in actions
            if a.get("action_type") == ActionType.BLOCK_IP.value and a.get("target")
        }
        primary_blocked = PRIMARY_IP in blocked_targets
        secondary_blocked = SECONDARY_IP in blocked_targets
        user_flagged = any(
            a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == THREAT_USER
            for a in actions
        )
        host_isolated = any(
            a.get("action_type") == ActionType.ISOLATE_HOST.value and a.get("target") == THREAT_HOST
            for a in actions
        )

        # ── Primary objectives ──────────────────────────────────────────
        if primary_blocked:
            score += 0.30
        if secondary_blocked:
            score += 0.15

        if user_flagged:
            score += 0.25

        if host_isolated:
            score += 0.15

        # ── False positives ─────────────────────────────────────────────
        fp_count = state.false_positives

        # Penalise for blocking the red-herring IP more
        if BENIGN_IP in blocked_targets:
            fp_count += 1  # extra penalty

        score -= fp_count * FP_PENALTY

        # ── Timeliness bonus ────────────────────────────────────────────
        if self._early_detection(state, threshold=4):
            score += 0.10

        return round(max(0.0, min(1.0, score)), 4)

    def _early_detection(self, state: SOCState, threshold: int) -> bool:
        for i, a in enumerate(state.agent_actions):
            if i >= threshold:
                break
            if a["action_type"] == ActionType.BLOCK_IP.value and any(d.endswith(a["target"] or "") for d in state.correct_detections):
                return True
        return False

    def explain(self, state: SOCState) -> dict:
        blocked_targets = {
            a.get("target")
            for a in state.agent_actions
            if a.get("action_type") == ActionType.BLOCK_IP.value and a.get("target")
        }
        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "primary_ip_blocked": PRIMARY_IP in blocked_targets,
            "secondary_ip_blocked": SECONDARY_IP in blocked_targets,
            "user_flagged": any(
                a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == THREAT_USER
                for a in state.agent_actions
            ),
            "host_isolated": any(
                a.get("action_type") == ActionType.ISOLATE_HOST.value and a.get("target") == THREAT_HOST
                for a in state.agent_actions
            ),
            "steps_taken": state.step_count,
            "false_positives": state.false_positives,
            "mitre_tactics": ["T1110 (Brute Force)", "T1078 (Valid Accounts)"]
        }
