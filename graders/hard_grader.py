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

        blocked_ips = {a["target"] for a in actions if a["action_type"] == ActionType.BLOCK_IP.value}
        isolated_hosts = {
            a["target"] for a in actions if a["action_type"] == ActionType.ISOLATE_HOST.value
        }
        flagged_users = {a["target"] for a in actions if a["action_type"] == ActionType.FLAG_USER.value}
        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)

        # ── Stage-by-stage scoring ───────────────────────────────────────
        # Stage 1: Recon — block C2 IP
        if C2_IP in blocked_ips:
            score += 0.15

        # Stage 2: Initial Access — isolate web server
        if "WEB-SRV-01" in isolated_hosts:
            score += 0.20

        # Stage 3: Lateral Movement — isolate DB + flag service account
        if "FINANCE-DB-01" in isolated_hosts:
            score += 0.20

        if COMPROMISED_USER in flagged_users:
            score += 0.10

        # Stage 4: Exfiltration — escalate for IR
        if escalated:
            score += 0.15

        # ── False positive penalty ─────────────────────────────────────
        fp_blocks = {ip for ip in blocked_ips if ip != C2_IP}
        fp_isolates = {h for h in isolated_hosts if h not in COMPROMISED_HOSTS}
        fp_flags = {u for u in flagged_users if u != COMPROMISED_USER}
        fp_count = len(fp_blocks) + len(fp_isolates) + len(fp_flags)
        score -= fp_count * FP_PENALTY

        # ── Ordering bonus ─────────────────────────────────────────────
        # The agent should have detected stages in correct order
        if self._detected_in_order(actions):
            score += 0.10

        # ── Speed bonus ────────────────────────────────────────────────
        if state.step_count <= 12 and self._all_stages_covered(blocked_ips, isolated_hosts, flagged_users, escalated):
            score += 0.10

        return round(max(0.0, min(1.0, score)), 4)

    def _all_stages_covered(self, blocked_ips: set, isolated_hosts: set, flagged_users: set, escalated: bool) -> bool:
        return (
            C2_IP in blocked_ips
            and "WEB-SRV-01" in isolated_hosts
            and "FINANCE-DB-01" in isolated_hosts
            and COMPROMISED_USER in flagged_users
            and escalated
        )

    def _detected_in_order(self, actions: list) -> bool:
        """
        Check if actions appear in stage order:
        block_ip → isolate WEB-SRV-01 → isolate FINANCE-DB-01 → escalate
        """
        stage_sequence = []
        for a in actions:
            if a["action_type"] == ActionType.BLOCK_IP.value and a["target"] == C2_IP:
                stage_sequence.append("recon")
            elif a["action_type"] == ActionType.ISOLATE_HOST.value and a["target"] == "WEB-SRV-01":
                stage_sequence.append("initial_access")
            elif a["action_type"] == ActionType.ISOLATE_HOST.value and a["target"] == "FINANCE-DB-01":
                stage_sequence.append("lateral")
            elif a["action_type"] == ActionType.ESCALATE_ALERT.value:
                stage_sequence.append("exfil")

        expected = ["recon", "initial_access", "lateral", "exfil"]
        # Check if expected is a subsequence of stage_sequence
        it = iter(stage_sequence)
        return all(stage in it for stage in expected)

    def explain(self, state: SOCState) -> dict:
        actions = state.agent_actions
        blocked_ips = {a["target"] for a in actions if a["action_type"] == ActionType.BLOCK_IP.value}
        isolated_hosts = {
            a["target"] for a in actions if a["action_type"] == ActionType.ISOLATE_HOST.value
        }
        flagged_users = {a["target"] for a in actions if a["action_type"] == ActionType.FLAG_USER.value}
        escalated = any(a["action_type"] == ActionType.ESCALATE_ALERT.value for a in actions)

        return {
            "task_id": self.TASK_ID,
            "total_score": self.grade(state),
            "stages": {
                "recon_detected": C2_IP in blocked_ips,
                "initial_access_contained": "WEB-SRV-01" in isolated_hosts,
                "lateral_movement_contained": "FINANCE-DB-01" in isolated_hosts,
                "service_account_flagged": COMPROMISED_USER in flagged_users,
                "escalated": escalated,
            },
            "detected_in_order": self._detected_in_order(actions),
            "steps_taken": state.step_count,
            "attack_stages_detected": state.attack_stages_detected,
            "false_positives": state.false_positives,
        }
