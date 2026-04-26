"""
SOC Simulator — Core Environment
==================================
OpenEnv-compliant implementation of the AI Cybersecurity Incident Response
Environment (SOC Simulator).

Implements the standard interface:
  reset()  → SOCObservation
  step()   → SOCObservation  (with reward, done, info)
  state()  → SOCState
"""

from __future__ import annotations

import sys
import os

# Allow running from server/ subfolder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from models import (
    ActionType, SOCAction, SOCObservation, SOCState, SystemState,
    ThreatLevel,
)
from tasks import EasyTask, MediumTask, HardTask
from graders import EasyGrader, MediumGrader, HardGrader
from env.schema_drift import SchemaDriftEngine


# ---------------------------------------------------------------------------
# Reward constants
# ---------------------------------------------------------------------------

class RewardConfig:
    """Dense reward function parameters."""

    # Positive rewards
    CORRECT_BLOCK_IP = 0.30
    CORRECT_FLAG_USER = 0.25
    CORRECT_ISOLATE_HOST = 0.25
    CORRECT_ESCALATE = 0.15
    CORRECT_IGNORE = 0.05        # Right to ignore benign events
    STAGE_DETECTION_BONUS = 0.10 # Per new attack stage discovered

    # Negative rewards
    FALSE_POSITIVE_PENALTY = -0.15   # Blocking wrong IP / flagging wrong user
    UNNECESSARY_IGNORE = -0.30       # Ignoring a confirmed threat
    REDUNDANT_ACTION = -0.05         # Same action taken twice
    TIMESTEP_COST = -0.02            # Small cost per step (encourages speed)

    # Terminal
    TASK_COMPLETION_BONUS = 0.25
    MISSED_THREAT_PENALTY = -0.40


TASK_REGISTRY = {
    "easy_phishing_login": (EasyTask, EasyGrader),
    "medium_brute_force_geo": (MediumTask, MediumGrader),
    "hard_apt_multistage": (HardTask, HardGrader),
}


class SOCEnvironment:
    """
    AI Cybersecurity SOC Simulator — OpenEnv-compliant environment.

    Usage
    -----
    env = SOCEnvironment()
    obs = env.reset(task_id="easy_phishing_login")
    obs = env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"))
    state = env.state
    """

    def __init__(self):
        self._state: Optional[SOCState] = None
        self._task = None
        self._grader = None
        self._current_task_id: Optional[str] = None
        self._step_history: list = []
        self._custom_params: Dict[str, Any] = {}
        self._schema_engine = SchemaDriftEngine()

    # -------------------------------------------------------------------------
    # OpenEnv API
    # -------------------------------------------------------------------------

    def reset(
        self,
        task_id: str = "easy_phishing_login",
        episode_id: Optional[str] = None,
        seed: Optional[int] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """
        Initialise a new episode for the given task.

        Parameters
        ----------
        task_id : str
            One of: easy_phishing_login | medium_brute_force_geo | hard_apt_multistage
        episode_id : str, optional
            Provide a fixed ID for reproducibility.
        seed : int, optional
            Unused (all tasks are deterministic). Accepted for API compatibility.

        Returns
        -------
        SOCObservation
            Initial observation for the episode.
        """
        if task_id not in TASK_REGISTRY:
            raise ValueError(
                f"Unknown task_id: {task_id!r}. "
                f"Valid options: {list(TASK_REGISTRY.keys())}"
            )

        task_cls, grader_cls = TASK_REGISTRY[task_id]
        self._task = task_cls(**kwargs)
        self._grader = grader_cls()
        self._current_task_id = task_id
        self._step_history = []

        ep_id = episode_id or str(uuid4())

        # Build state from task definition
        threats = self._task.get_threat_targets()

        # Flatten all true threat identifiers
        true_threats = []
        if "ip" in threats:
            true_threats.append(threats["ip"])
        if "ips" in threats:
            true_threats.extend(list(threats["ips"]))
        if "c2_ip" in threats:
            true_threats.append(threats["c2_ip"])
        if "user" in threats:
            true_threats.append(threats["user"])
        if "compromised_user" in threats:
            true_threats.append(threats["compromised_user"])
        if "host" in threats:
            true_threats.append(threats["host"])
        if "compromised_hosts" in threats:
            true_threats.extend(list(threats.get("compromised_hosts", [])))

        self._state = SOCState(
            episode_id=ep_id,
            step_count=0,
            task_id=task_id,
            task_completed=False,
            true_threats=true_threats,
            agent_actions=[],
            correct_detections=[],
            false_positives=0,
            false_negatives=0,
            total_reward=0.0,
            start_time=datetime.utcnow(),
            attack_stages_detected=[],
        )

        initial_obs = self._task.get_initial_observation(ep_id)
        
        self._custom_params = kwargs
        if self._custom_params.get("enable_schema_drift"):
            # Step 0 drift (initializes to v1 and sets state)
            self._schema_engine.maybe_drift(0)
            initial_obs.recent_events = self._schema_engine.apply_drift(initial_obs.recent_events)
            initial_obs.schema_version = self._schema_engine.current_version
            
        return initial_obs

    def step(
        self,
        action: SOCAction,
        **kwargs: Any,
    ) -> SOCObservation:
        """
        Execute one analyst action and return the resulting observation.

        Parameters
        ----------
        action : SOCAction
            The action chosen by the agent.

        Returns
        -------
        SOCObservation
            Contains reward, done flag, updated alerts, and system state.
        """
        if self._state is None:
            raise RuntimeError("Call reset() before step().")

        # Stamp the action timestamp
        action.step_taken_at = datetime.utcnow()
        action_dict = {
            "action_type": action.action_type,
            "target": action.target,
            "reason": action.reason,
            "confidence": action.confidence,
            "step": self._state.step_count,
        }
        self._state.agent_actions.append(action_dict)
        self._state.step_count += 1

        # Compute per-step reward
        reward, info = self._compute_reward(action, action_dict)
        self._state.total_reward += reward

        # Check termination conditions
        max_steps = self._task.MAX_STEPS
        done = self._state.step_count >= max_steps or self._state.task_completed

        if done and not self._state.task_completed:
            # End-of-episode: apply missed-threat penalty
            self._apply_endgame_penalties()
            self._state.task_completed = True

        # Build next observation
        obs = self._build_observation(reward=reward, done=done, info=info)
        
        if self._custom_params.get("enable_schema_drift"):
            self._schema_engine.maybe_drift(self._state.step_count)
            obs.recent_events = self._schema_engine.apply_drift(obs.recent_events)
            obs.schema_version = self._schema_engine.current_version
            
        return obs

    @property
    def state(self) -> Optional[SOCState]:
        """Return the current internal episode state."""
        return self._state

    # -------------------------------------------------------------------------
    # Reward computation
    # -------------------------------------------------------------------------

    def _compute_reward(
        self, action: SOCAction, action_dict: dict
    ) -> Tuple[float, dict]:
        """
        Dense reward function — gives signal at every step.

        Returns (reward: float, info: dict)
        """
        reward = RewardConfig.TIMESTEP_COST  # Base cost per step
        info = {"action_type": action.action_type, "target": action.target}
        threats = self._task.get_threat_targets()

        # ── Detect duplicate actions ────────────────────────────────────
        prev_actions = self._state.agent_actions[:-1]  # Exclude current
        is_duplicate = any(
            a["action_type"] == action.action_type and a["target"] == action.target
            for a in prev_actions
        )
        if is_duplicate:
            reward += RewardConfig.REDUNDANT_ACTION
            info["duplicate"] = True
            return reward, info

        # ── Evaluate action against ground truth ─────────────────────────
        if action.action_type == ActionType.BLOCK_IP:
            reward, info = self._evaluate_block_ip(action, threats, reward, info)

        elif action.action_type == ActionType.FLAG_USER:
            reward, info = self._evaluate_flag_user(action, threats, reward, info)

        elif action.action_type == ActionType.ISOLATE_HOST:
            reward, info = self._evaluate_isolate_host(action, threats, reward, info)

        elif action.action_type == ActionType.ESCALATE_ALERT:
            reward, info = self._evaluate_escalate(threats, reward, info)

        elif action.action_type == ActionType.IGNORE:
            # Penalise only if there are unresolved critical threats
            unresolved = self._get_unresolved_threats()
            if unresolved:
                reward += RewardConfig.UNNECESSARY_IGNORE
                info["ignored_active_threat"] = True
            else:
                reward += RewardConfig.CORRECT_IGNORE
                info["correct_ignore"] = True

        # Track hard task stage progression
        if self._current_task_id == "hard_apt_multistage":
            self._update_hard_task_stage(action, threats)

        # Early success termination when all ground-truth threats are handled.
        # This prevents exploitative "ignore until max_steps" policies from
        # receiving comparable returns to decisive mitigation.
        unresolved = self._get_unresolved_threats()
        if not unresolved and not self._state.task_completed:
            reward += RewardConfig.TASK_COMPLETION_BONUS
            info["task_completed"] = True
            info["completion_bonus"] = RewardConfig.TASK_COMPLETION_BONUS
            self._state.task_completed = True

        return reward, info

    def _evaluate_block_ip(self, action: SOCAction, threats: dict, reward: float, info: dict) -> Tuple[float, dict]:
        """Check if the blocked IP is malicious or benign."""
        target_ip = action.target or ""
        threat_ips = set()

        if "ip" in threats:
            threat_ips.add(threats["ip"])
        if "ips" in threats:
            threat_ips.update(threats["ips"])
        if "c2_ip" in threats:
            threat_ips.add(threats["c2_ip"])

        if target_ip in threat_ips:
            reward += RewardConfig.CORRECT_BLOCK_IP
            self._state.correct_detections.append(f"block:{target_ip}")
            info["correct"] = True
        else:
            reward += RewardConfig.FALSE_POSITIVE_PENALTY
            self._state.false_positives += 1
            info["false_positive"] = True

        return reward, info

    def _evaluate_flag_user(self, action: SOCAction, threats: dict, reward: float, info: dict) -> Tuple[float, dict]:
        """Check if the flagged user is compromised."""
        target_user = action.target or ""
        threat_users = set()

        if "user" in threats:
            threat_users.add(threats["user"])
        if "compromised_user" in threats:
            threat_users.add(threats["compromised_user"])

        if target_user in threat_users:
            reward += RewardConfig.CORRECT_FLAG_USER
            self._state.correct_detections.append(f"flag:{target_user}")
            info["correct"] = True
        else:
            reward += RewardConfig.FALSE_POSITIVE_PENALTY
            self._state.false_positives += 1
            info["false_positive"] = True

        return reward, info

    def _evaluate_isolate_host(self, action: SOCAction, threats: dict, reward: float, info: dict) -> Tuple[float, dict]:
        """Check if the isolated host is compromised."""
        target_host = action.target or ""
        threat_hosts = set()

        if "host" in threats:
            threat_hosts.add(threats["host"])
        if "compromised_hosts" in threats:
            threat_hosts.update(threats["compromised_hosts"])

        if target_host in threat_hosts:
            reward += RewardConfig.CORRECT_ISOLATE_HOST
            self._state.correct_detections.append(f"isolate:{target_host}")
            info["correct"] = True
        else:
            reward += RewardConfig.FALSE_POSITIVE_PENALTY
            self._state.false_positives += 1
            info["false_positive"] = True

        return reward, info

    def _evaluate_escalate(self, threats: dict, reward: float, info: dict) -> Tuple[float, dict]:
        """Escalate is rewarded when there are active unresolved critical threats."""
        unresolved = self._get_unresolved_threats()
        if unresolved or self._current_task_id == "hard_apt_multistage":
            reward += RewardConfig.CORRECT_ESCALATE
            self._state.correct_detections.append("escalate:system")
            info["correct"] = True
        else:
            # Escalating benign situation wastes time
            reward += RewardConfig.FALSE_POSITIVE_PENALTY / 2
            info["unnecessary_escalation"] = True

        return reward, info

    def _get_unresolved_threats(self) -> list:
        """Return true threats not yet addressed by the agent."""
        addressed = set(self._state.correct_detections)
        threats = self._task.get_threat_targets()
        all_threat_ids = set()

        for key in ("ip", "c2_ip"):
            if key in threats:
                all_threat_ids.add(f"block:{threats[key]}")
        for ip in threats.get("ips", []):
            all_threat_ids.add(f"block:{ip}")
        for key in ("user", "compromised_user"):
            if key in threats:
                all_threat_ids.add(f"flag:{threats[key]}")
        for host in threats.get("compromised_hosts", []):
            all_threat_ids.add(f"isolate:{host}")
        if "host" in threats:
            all_threat_ids.add(f"isolate:{threats['host']}")
            
        if self._current_task_id == "hard_apt_multistage":
            all_threat_ids.add("escalate:system")

        return list(all_threat_ids - addressed)

    def _update_hard_task_stage(self, action: SOCAction, threats: dict) -> None:
        """Track which attack stages the agent has responded to (hard task only)."""
        stage_map = {
            f"block:{threats.get('c2_ip')}": "reconnaissance",
            "isolate:WEB-SRV-01": "initial_access",
            "isolate:FINANCE-DB-01": "lateral_movement",
        }
        for detection in self._state.correct_detections:
            stage = stage_map.get(detection)
            if stage and stage not in self._state.attack_stages_detected:
                self._state.attack_stages_detected.append(stage)
                self._state.total_reward += RewardConfig.STAGE_DETECTION_BONUS

    def _apply_endgame_penalties(self):
        """Apply missed-threat penalties at episode end."""
        unresolved = self._get_unresolved_threats()
        penalty = len(unresolved) * RewardConfig.MISSED_THREAT_PENALTY
        self._state.total_reward += penalty
        self._state.false_negatives = len(unresolved)

    # -------------------------------------------------------------------------
    # Observation building
    # -------------------------------------------------------------------------

    def _build_observation(
        self, reward: float, done: bool, info: dict
    ) -> SOCObservation:
        """Construct the SOCObservation that the agent receives after each step."""
        threats = self._task.get_threat_targets()

        # Determine which events/alerts to show (hard task reveals more as it progresses)
        events = []
        alerts = []

        if self._current_task_id == "hard_apt_multistage":
            current_stage = self._determine_hard_stage()
            events = self._task.get_events_for_stage(current_stage)
            alerts = self._task.get_alerts_for_stage(current_stage)
            attack_stage = current_stage
        else:
            # ── Live reactive observations for easy / medium tasks ──────
            # Pull the base scenario events and alerts, then filter out
            # alerts whose primary threat targets have already been
            # correctly addressed by the agent.
            base_obs = self._task.get_initial_observation(self._state.episode_id)
            events = base_obs.recent_events
            addressed = set(self._state.correct_detections)

            # Filter alerts: remove those whose related threat is resolved
            live_alerts = []
            for alert in base_obs.active_alerts:
                alert_resolved = False
                desc = (alert.description or "") + " " + (alert.title or "")
                # Check if any correctly-detected target appears in this alert
                for det in addressed:
                    # det is like "block:185.220.101.47" or "flag:alice.chen"
                    _, target_val = det.split(":", 1) if ":" in det else ("", det)
                    if target_val and target_val in desc:
                        alert_resolved = True
                        break
                if not alert_resolved:
                    live_alerts.append(alert)

            alerts = live_alerts
            attack_stage = None

        # Build system state from current detections
        blocked_ips = [
            a["target"]
            for a in self._state.agent_actions
            if a["action_type"] == ActionType.BLOCK_IP
        ]
        flagged_users = [
            a["target"]
            for a in self._state.agent_actions
            if a["action_type"] == ActionType.FLAG_USER
        ]
        isolated_hosts = [
            a["target"]
            for a in self._state.agent_actions
            if a["action_type"] == ActionType.ISOLATE_HOST
        ]

        # Risk diminishes as threats are addressed
        threat_total = max(len(threats.get("ips", [])) + 1, 1)
        unresolved_count = len(self._get_unresolved_threats())
        risk_score = min(1.0, unresolved_count / threat_total)

        system_state = SystemState(
            active_connections=max(0, 500 - self._state.step_count * 30),
            blocked_ips=list(set(blocked_ips)),
            flagged_users=list(set(flagged_users)),
            isolated_hosts=list(set(isolated_hosts)),
            open_incidents=max(0, 3 - len(self._state.correct_detections)),
            risk_score=round(risk_score, 2),
        )

        return SOCObservation(
            done=done,
            reward=reward,
            metadata={
                "episode_id": self._state.episode_id,
                "total_reward": self._state.total_reward,
                "step_info": info,
                "correct_detections": self._state.correct_detections,
                "false_positives": self._state.false_positives,
            },
            task_id=self._current_task_id,
            step_number=self._state.step_count,
            timestamp=datetime.utcnow(),
            recent_events=events,
            active_alerts=alerts,
            system_state=system_state,
            network_anomaly_score=round(risk_score * 0.9 + 0.05, 2),
            attack_stage=attack_stage,
        )

    def _determine_hard_stage(self) -> str:
        """Decide which attack stage to surface based on step count."""
        step = self._state.step_count
        if step <= 3:
            return "reconnaissance"
        elif step <= 6:
            return "initial_access"
        elif step <= 10:
            return "lateral_movement"
        else:
            return "exfiltration"

    # -------------------------------------------------------------------------
    # Grading
    # -------------------------------------------------------------------------

    def get_final_score(self) -> float:
        """Run the task grader on the completed episode and return [0, 1] score."""
        if self._state is None:
            raise RuntimeError("No episode to grade. Call reset() first.")
        return self._grader.grade(self._state)

    def get_score_explanation(self) -> dict:
        """Return a detailed scoring breakdown."""
        if self._state is None:
            raise RuntimeError("No episode to grade. Call reset() first.")
        return self._grader.explain(self._state)
