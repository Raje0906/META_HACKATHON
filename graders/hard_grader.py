"""
HARD TASK GRADER
================
Evaluates agent performance on the multi-stage APT attack.

Scoring Rubric (total: 1.0)
────────────────────────────
Stage coverage (each stage = 0.20):
  • Recon detected  → block_ip(198.51.100.77)            +0.15
  • Initial access  → isolate_host(WEB-SRV-01)           +0.20
  • Lateral move    → isolate_host(FINANCE-DB-01)         +0.20
                    + flag_user(backup-svc)               +0.10
  • Exfiltration    → escalate_alert                      +0.15
FP penalty          → -0.08 per false action             (deducted)
Stage ordering      → +0.10 bonus if detected in order   (bonus, capped 1.0)
Speed bonus         → +0.10 if all stages within 12 steps (bonus, capped 1.0)
"""

from __future__ import annotations

from models import ActionType, SOCState


C2_IP = "198.51.100.77"
COMPROMISED_HOSTS = {"WEB-SRV-01", "FINANCE-DB-01"}
COMPROMISED_USER = "backup-svc"
ALL_STAGES = ["reconnaissance", "initial_access", "lateral_movement", "exfiltration"]
FP_PENALTY = 0.08


class HardGrader:
    """Deterministic grader for the HARD multi-stage APT task."""

    TASK_ID = "hard_apt_multistage"

    def grade(self, state: SOCState) -> float:
        actions = state.agent_actions
        score = 0.0

        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)
        user_flags = [
            a for a in actions
            if a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == COMPROMISED_USER
        ]

        # ── Stage-by-stage scoring ───────────────────────────────────────
        if "reconnaissance" in state.attack_stages_detected:
            score += 0.15

        if "initial_access" in state.attack_stages_detected:
            score += 0.20

        if "lateral_movement" in state.attack_stages_detected:
            score += 0.20

        if user_flags:
            score += 0.10

        if escalated:
            score += 0.15

        # ── False positive penalty ─────────────────────────────────────
        score -= state.false_positives * FP_PENALTY

        # ── Ordering bonus ─────────────────────────────────────────────
        if self._detected_in_order(state):
            score += 0.10

        # ── Speed bonus ────────────────────────────────────────────────
        if state.step_count <= 12 and self._all_stages_covered(state, escalated):
            score += 0.10

        return round(max(0.0, min(1.0, score)), 4)

    def _all_stages_covered(self, state: SOCState, escalated: bool) -> bool:
        user_flags = [
            a for a in state.agent_actions
            if a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == COMPROMISED_USER
        ]
        return (
            "reconnaissance" in state.attack_stages_detected
            and "initial_access" in state.attack_stages_detected
            and "lateral_movement" in state.attack_stages_detected
            and len(user_flags) >= 1
            and escalated
        )

    def _detected_in_order(self, state: SOCState) -> bool:
        """Check if stages were detected sequentially."""
        expected = ["reconnaissance", "initial_access", "lateral_movement"]
        stages = state.attack_stages_detected
        
        # Check if the detected stages follow the correct order
        last_idx = -1
        for stage in stages:
            if stage in expected:
                idx = expected.index(stage)
                if idx < last_idx:
                    return False
                last_idx = idx
                
        # Also check if escalate happened after lateral
        if any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in state.agent_actions):
            if "lateral_movement" in stages and stages[-1] != "lateral_movement":
                pass
                
        return True

    def explain(self, state: SOCState) -> dict:
        actions = state.agent_actions
        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)
        user_flags = [
            a for a in actions
            if a.get("action_type") == ActionType.FLAG_USER.value and a.get("target") == COMPROMISED_USER
        ]

        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "stages": {
                "recon_detected": "reconnaissance" in state.attack_stages_detected,
                "initial_access_contained": "initial_access" in state.attack_stages_detected,
                "lateral_movement_contained": "lateral_movement" in state.attack_stages_detected,
                "service_account_flagged": len(user_flags) > 0,
                "escalated": escalated,
            },
            "detected_in_order": self._detected_in_order(state),
            "steps_taken": state.step_count,
            "attack_stages_detected": state.attack_stages_detected,
            "false_positives": state.false_positives,
            "mitre_tactics": ["T1190 (Exploit Public-Facing Application)", "T1090 (Proxy)"]
        }
