"""
RedAgent — Adaptive Adversarial Attacker
=========================================
Simulates a persistent threat actor that learns from the blue agent's
previous episode actions and mutates the attack scenario to evade detection.

Behavior
--------
- Maintains a memory of the last episode's blue agent actions
  (blocked IPs, flagged users, isolated hosts).
- At the start of each new episode, generates a mutated attack scenario:
    a) IP Rotation  — replaces blocked IPs with new ones from RFC 5737 /
       IANA documentation ranges (safe for simulation).
    b) Credential Rotation — replaces flagged usernames with alternates
       from a realistic service-account pool.
    c) Timing Jitter — shifts event timestamps by ±5 minutes to evade
       time-based detection rules.
    d) Tactic Escalation — adds T1027 Obfuscation when blue score > 0.75.
- Tracks its own score: how many attacks went undetected by the blue agent.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# IP & Credential pools (RFC 5737 / IANA documentation ranges — safe for sim)
# ---------------------------------------------------------------------------

# 198.51.100.0/24 — TEST-NET-2 (RFC 5737)
_ATTACKER_IP_POOL_198: List[str] = [
    f"198.51.100.{i}" for i in range(10, 250, 7)
]

# 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
_ATTACKER_IP_POOL_203: List[str] = [
    f"203.0.113.{i}" for i in range(5, 250, 9)
]

ATTACKER_IP_POOL: List[str] = _ATTACKER_IP_POOL_198 + _ATTACKER_IP_POOL_203

# Realistic service-account username pool
CREDENTIAL_POOL: List[str] = [
    "backup-svc",
    "svc-account",
    "it-admin",
    "db-user",
    "devops",
    "svc-monitor",
    "svc-deploy",
    "net-admin",
    "infra-svc",
    "support-agent",
    "ops-admin",
    "svc-backup02",
]

# MITRE ATT&CK techniques available for tactic escalation
ESCALATION_TECHNIQUES: List[Dict[str, str]] = [
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Attacker obfuscated payloads to evade static-analysis "
            "detection rules. Encoded scripts detected in process arguments."
        ),
    },
    {
        "id": "T1070",
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "description": (
            "Event log entries cleared on compromised host. File timestamps "
            "modified to frustrate forensic timeline reconstruction."
        ),
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": (
            "Malicious binary renamed to mimic legitimate system process "
            "(svchost.exe, lsass.exe) to bypass process-name filters."
        ),
    },
]


# ---------------------------------------------------------------------------
# Blue-agent memory snapshot (passed to get_mutated_scenario)
# ---------------------------------------------------------------------------

@dataclass
class BlueMemory:
    """
    Summary of the last episode's blue-agent responses.

    Fields
    ------
    blocked_ips     : Set of IPs the blue agent blocked.
    flagged_users   : Set of usernames the blue agent flagged.
    isolated_hosts  : Set of host IDs the blue agent isolated.
    episode_score   : Final grader score in [0, 1] for the last episode.
    """
    blocked_ips: Set[str] = field(default_factory=set)
    flagged_users: Set[str] = field(default_factory=set)
    isolated_hosts: Set[str] = field(default_factory=set)
    episode_score: float = 0.0


# ---------------------------------------------------------------------------
# RedAgent
# ---------------------------------------------------------------------------

class RedAgent:
    """
    Adaptive adversarial attacker that mutates scenarios based on blue-agent
    memory from the previous episode.

    Usage
    -----
    red = RedAgent()

    # After first episode, extract blue memory from SOCState + final score:
    blue_mem = BlueMemory(
        blocked_ips={"185.220.101.47"},
        flagged_users={"alice.chen"},
        isolated_hosts=set(),
        episode_score=0.82,
    )
    mutated = red.get_mutated_scenario("easy_phishing_login", blue_mem)

    # mutated is a dict of overrides to apply to the task's scenario params.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        """
        Parameters
        ----------
        seed : int, optional
            RNG seed for reproducibility.  If None, a random seed is used.
        """
        self._rng = random.Random(seed)

        # History tracking
        self._session_history: List[Dict[str, Any]] = []
        self._undetected_attacks: int = 0
        self._total_attack_attempts: int = 0

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_mutated_scenario(
        self,
        task_id: str,
        blue_memory: BlueMemory,
    ) -> Dict[str, Any]:
        """
        Generate a mutated scenario dict based on blue-agent memory.

        The returned dict maps scenario parameter names to their mutated
        values.  Callers (e.g. DynamicInputPipeline or SOCEnvironment) should
        merge these overrides on top of the base task defaults.

        Parameters
        ----------
        task_id : str
            One of the registered task IDs.
        blue_memory : BlueMemory
            Actions taken by the blue agent in the previous episode.

        Returns
        -------
        dict
            Keys: attacker_ip, attacker_ips (list), target_user,
                  timestamp_jitter_minutes, additional_techniques,
                  escalation_applied.
        """
        mutations: Dict[str, Any] = {
            "task_id": task_id,
            "attacker_ip": None,
            "attacker_ips": [],
            "target_user": None,
            "timestamp_jitter_minutes": 0,
            "additional_techniques": [],
            "escalation_applied": False,
        }

        # (a) IP Rotation ────────────────────────────────────────────────────
        if blue_memory.blocked_ips:
            # Pick IPs from pool that have NOT been blocked yet
            fresh_ips = [
                ip for ip in ATTACKER_IP_POOL
                if ip not in blue_memory.blocked_ips
            ]
            if fresh_ips:
                new_ip = self._rng.choice(fresh_ips)
                mutations["attacker_ip"] = new_ip
                # Also provide a small pool of rotated IPs for multi-IP tasks
                pool_candidates = [ip for ip in fresh_ips if ip != new_ip]
                mutations["attacker_ips"] = self._rng.sample(
                    pool_candidates, min(3, len(pool_candidates))
                )

        # (b) Credential Rotation ────────────────────────────────────────────
        if blue_memory.flagged_users:
            fresh_creds = [
                u for u in CREDENTIAL_POOL
                if u not in blue_memory.flagged_users
            ]
            if fresh_creds:
                mutations["target_user"] = self._rng.choice(fresh_creds)

        # (c) Timing Jitter — ±5 minutes (value in minutes, sign included) ──
        jitter_min = self._rng.randint(-5, 5)
        mutations["timestamp_jitter_minutes"] = jitter_min

        # (d) Tactic Escalation — triggered when blue score > 0.75 ──────────
        if blue_memory.episode_score > 0.75:
            technique = self._rng.choice(ESCALATION_TECHNIQUES)
            mutations["additional_techniques"] = [technique]
            mutations["escalation_applied"] = True

        # Record mutation for internal history
        self._session_history.append({
            "task_id": task_id,
            "blue_score": blue_memory.episode_score,
            "mutations": mutations,
        })
        self._total_attack_attempts += 1

        return mutations

    def apply_jitter_to_timestamp(
        self, ts: datetime, jitter_minutes: int
    ) -> datetime:
        """
        Shift a datetime by jitter_minutes (which may be negative).

        Parameters
        ----------
        ts : datetime
            Original event timestamp.
        jitter_minutes : int
            Offset in minutes (negative or positive).

        Returns
        -------
        datetime
            Jittered timestamp.
        """
        return ts + timedelta(minutes=jitter_minutes)

    def record_undetected_attack(self) -> None:
        """
        Call this when a red-agent attack event went undetected by the blue
        agent (i.e. a false negative in grading).  Increments internal score.
        """
        self._undetected_attacks += 1

    # -------------------------------------------------------------------------
    # Score / Stats
    # -------------------------------------------------------------------------

    @property
    def red_score(self) -> float:
        """
        Fraction of attacks that went undetected in [0, 1].

        0.0 — blue agent caught everything.
        1.0 — blue agent caught nothing.
        """
        if self._total_attack_attempts == 0:
            return 0.0
        return self._undetected_attacks / self._total_attack_attempts

    @property
    def session_history(self) -> List[Dict[str, Any]]:
        """Read-only view of all mutation records this session."""
        return list(self._session_history)

    def reset_session(self) -> None:
        """
        Clear session history and score counters.

        Call this when starting a completely new evaluation run (not between
        episodes — mutations accumulate across episodes by design).
        """
        self._session_history = []
        self._undetected_attacks = 0
        self._total_attack_attempts = 0

    # -------------------------------------------------------------------------
    # Helpers: build blue-memory from SOCState
    # -------------------------------------------------------------------------

    @staticmethod
    def extract_blue_memory(
        agent_actions: List[Dict[str, Any]],
        episode_score: float,
    ) -> BlueMemory:
        """
        Convenience factory — builds a BlueMemory from the raw action history
        stored in SOCState.agent_actions.

        Parameters
        ----------
        agent_actions : list of dicts
            SOCState.agent_actions (list of action dicts with keys
            action_type, target, ...).
        episode_score : float
            Final grader score for the episode.

        Returns
        -------
        BlueMemory
        """
        blocked: Set[str] = set()
        flagged: Set[str] = set()
        isolated: Set[str] = set()

        for act in agent_actions:
            atype = str(act.get("action_type", "")).lower()
            target = act.get("target")
            if target is None:
                continue
            if "block_ip" in atype:
                blocked.add(target)
            elif "flag_user" in atype:
                flagged.add(target)
            elif "isolate_host" in atype:
                isolated.add(target)

        return BlueMemory(
            blocked_ips=blocked,
            flagged_users=flagged,
            isolated_hosts=isolated,
            episode_score=episode_score,
        )
