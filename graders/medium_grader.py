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

        blocked_ips = {a["target"] for a in actions if a["action_type"] == ActionType.BLOCK_IP}
        flagged_users = {a["target"] for a in actions if a["action_type"] == ActionType.FLAG_USER}
        isolated_hosts = {
            a["target"] for a in actions if a["action_type"] == ActionType.ISOLATE_HOST
        }

        # ── Primary objectives ──────────────────────────────────────────
        if PRIMARY_IP in blocked_ips:
            score += 0.30

        if SECONDARY_IP in blocked_ips:
            score += 0.15

        if THREAT_USER in flagged_users:
            score += 0.25

        if THREAT_HOST in isolated_hosts:
            score += 0.15

        # ── False positives ─────────────────────────────────────────────
        threat_ips = {PRIMARY_IP, SECONDARY_IP}
        fp_blocks = {ip for ip in blocked_ips if ip not in threat_ips}
        fp_flags = {u for u in flagged_users if u != THREAT_USER}
        fp_isolates = {h for h in isolated_hosts if h != THREAT_HOST}
        fp_count = len(fp_blocks) + len(fp_flags) + len(fp_isolates)

        # Penalise for blocking the red-herring IP more
        if BENIGN_IP in blocked_ips:
            fp_count += 1  # extra penalty

        score -= fp_count * FP_PENALTY

        # ── Timeliness bonus ────────────────────────────────────────────
        if self._early_detection(actions, threshold=4):
            score += 0.10

        return round(max(0.0, min(1.0, score)), 4)

    def _early_detection(self, actions: list, threshold: int) -> bool:
        for i, a in enumerate(actions):
            if i >= threshold:
                break
            if a["action_type"] == ActionType.BLOCK_IP and a["target"] == PRIMARY_IP:
                return True
        return False

    def explain(self, state: SOCState) -> dict:
        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "primary_ip_blocked": any(
                a["action_type"] == ActionType.BLOCK_IP and a["target"] == PRIMARY_IP
                for a in state.agent_actions
            ),
            "secondary_ip_blocked": any(
                a["action_type"] == ActionType.BLOCK_IP and a["target"] == SECONDARY_IP
                for a in state.agent_actions
            ),
            "user_flagged": any(
                a["action_type"] == ActionType.FLAG_USER and a["target"] == THREAT_USER
                for a in state.agent_actions
            ),
            "host_isolated": any(
                a["action_type"] == ActionType.ISOLATE_HOST and a["target"] == THREAT_HOST
                for a in state.agent_actions
            ),
            "steps_taken": state.step_count,
            "false_positives": state.false_positives,
        }
