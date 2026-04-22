"""
MEDIUM TASK — Detect Suspicious Behaviour (Brute-Force + Geo Anomaly)
=======================================================================
Scenario:
  The SOC receives 23 failed login attempts against the finance server from
  3 different source IPs over 8 minutes, followed by a single success from
  a new geographic location.  The patterns indicate a credential-stuffing or
  password-spray attack that succeeded.  The agent must correlate the events
  and take action to stop the intrusion.

Difficulty: MEDIUM
Max steps  : 8
Deterministic seed: 123
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from models import (
    ActionType, Alert, EventType, SecurityEvent, SOCObservation,
    SystemState, ThreatLevel,
)


# ---------------------------------------------------------------------------
# Synthetic brute-force events (deterministic)
# ---------------------------------------------------------------------------

def _make_fail_event(idx: int, ip: str, minute_offset: int, country: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=f"EVT-BF-{idx:03d}",
        timestamp=datetime(2024, 7, 22, 2, minute_offset, idx % 60),
        event_type=EventType.LOGIN_FAILURE,
        source_ip=ip,
        dest_ip="10.10.5.20",
        user_id="finance.admin",
        host_id="FINANCE-SRV-01",
        country=country,
        details={
            "auth_method": "password",
            "failure_reason": "INVALID_CREDENTIALS",
            "attempt_number": idx,
        },
        raw_log=(
            f"2024-07-22T02:{minute_offset:02d}:{idx % 60:02d}Z [SSH] FAIL "
            f"user=finance.admin src={ip} ({country}) target=FINANCE-SRV-01"
        ),
    )


# 23 failed logins from 3 IPs
BRUTE_FORCE_EVENTS: List[SecurityEvent] = []
_ip_pool = [
    ("45.142.212.100", "CN"),
    ("91.108.56.22", "CN"),
    ("77.88.55.88", "DE"),   # This one is a red herring — it's a legit scanner
]
for i in range(23):
    ip, country = _ip_pool[i % 3]
    BRUTE_FORCE_EVENTS.append(_make_fail_event(i + 1, ip, i // 5, country))

# Successful login after brute-force
SUCCESS_EVENT = SecurityEvent(
    event_id="EVT-BF-024",
    timestamp=datetime(2024, 7, 22, 2, 8, 14),
    event_type=EventType.LOGIN_SUCCESS,
    source_ip="45.142.212.100",
    dest_ip="10.10.5.20",
    user_id="finance.admin",
    host_id="FINANCE-SRV-01",
    country="CN",
    details={
        "auth_method": "password",
        "usual_country": "US",
        "risk_signal": "geo_anomaly + brute_force_followup",
        "mfa_bypassed": False,
        "session_id": "sess-ff91e4",
        "commands_run": ["id", "whoami", "cat /etc/passwd"],
    },
    raw_log=(
        "2024-07-22T02:08:14Z [SSH] SUCCESS user=finance.admin "
        "src=45.142.212.100 (CN) target=FINANCE-SRV-01 cmds=[id,whoami,cat /etc/passwd]"
    ),
)

# Benign noise events
BENIGN_EVENTS: List[SecurityEvent] = [
    SecurityEvent(
        event_id="EVT-N-001",
        timestamp=datetime(2024, 7, 22, 2, 1, 0),
        event_type=EventType.DNS_QUERY,
        source_ip="10.0.0.50",
        user_id=None,
        host_id="DEV-LAPTOP-12",
        country="US",
        details={"domain": "update.microsoft.com", "record_type": "A"},
        raw_log="2024-07-22T02:01:00Z [DNS] QUERY host=DEV-LAPTOP-12 domain=update.microsoft.com",
    ),
    SecurityEvent(
        event_id="EVT-N-002",
        timestamp=datetime(2024, 7, 22, 2, 3, 30),
        event_type=EventType.FILE_ACCESS,
        source_ip="10.10.2.11",
        user_id="jane.doe",
        host_id="WORKSTATION-03",
        country="US",
        details={"file": "/reports/q2_budget.xlsx", "action": "read"},
        raw_log="2024-07-22T02:03:30Z [FILE-AUDIT] READ user=jane.doe file=/reports/q2_budget.xlsx",
    ),
]

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

BRUTE_FORCE_ALERT = Alert(
    alert_id="ALT-101",
    title="Brute-Force Attack on FINANCE-SRV-01 (finance.admin)",
    description=(
        "23 failed SSH login attempts against finance.admin on FINANCE-SRV-01 "
        "from 2 Chinese IPs over 8 minutes.  Consistent with password-spray or "
        "credential-stuffing attack using a leaked credentials list."
    ),
    threat_level=ThreatLevel.HIGH,
    related_events=[e.event_id for e in BRUTE_FORCE_EVENTS],
    anomaly_score=0.88,
    triggered_at=datetime(2024, 7, 22, 2, 6, 0),
    mitre_tactic="Credential Access",
    mitre_technique="T1110.003",  # Password Spraying
)

GEO_ANOMALY_ALERT = Alert(
    alert_id="ALT-102",
    title="Geo-Anomaly: finance.admin authenticated from China",
    description=(
        "finance.admin successfully authenticated via SSH from China "
        "(45.142.212.100) immediately following 23 failed attempts. "
        "Account usually accessed from the US.  Post-auth recon commands "
        "detected: id, whoami, /etc/passwd access."
    ),
    threat_level=ThreatLevel.CRITICAL,
    related_events=["EVT-BF-024"] + [e.event_id for e in BRUTE_FORCE_EVENTS],
    anomaly_score=0.95,
    triggered_at=datetime(2024, 7, 22, 2, 8, 30),
    mitre_tactic="Initial Access",
    mitre_technique="T1078.001",  # Default Accounts
)

# Ground truth
THREAT_IPS = {"45.142.212.100", "91.108.56.22"}
THREAT_USER = "finance.admin"
THREAT_HOST = "FINANCE-SRV-01"

ALL_EVENTS = BENIGN_EVENTS + BRUTE_FORCE_EVENTS + [SUCCESS_EVENT]


class MediumTask:
    """
    Task definition for the MEDIUM scenario.

    The agent must correlate brute-force failures with a geo-anomaly success.
    Correct response: block primary attacker IPs and flag compromised user.
    """

    TASK_ID = "medium_brute_force_geo"
    MAX_STEPS = 8

    def __init__(self, **kwargs):
        pass
    DESCRIPTION = (
        "23 failed SSH logins against the finance server from Chinese IPs, "
        "followed by a successful login with post-auth recon commands.  "
        "Identify the attacker IPs, compromised user, and affected host."
    )

    def get_initial_observation(self, episode_id: str) -> SOCObservation:
        return SOCObservation(
            done=False,
            reward=0.0,
            metadata={"episode_id": episode_id},
            task_id=self.TASK_ID,
            step_number=0,
            timestamp=datetime(2024, 7, 22, 2, 9, 0),
            recent_events=ALL_EVENTS[-15:],   # Show last 15 events (realistic SIEM window)
            active_alerts=[BRUTE_FORCE_ALERT, GEO_ANOMALY_ALERT],
            system_state=SystemState(
                active_connections=312,
                blocked_ips=[],
                flagged_users=[],
                isolated_hosts=[],
                open_incidents=1,
                risk_score=0.74,
            ),
            network_anomaly_score=0.79,
        )

    def get_all_events(self) -> List[SecurityEvent]:
        return ALL_EVENTS

    def get_threat_targets(self) -> dict:
        return {
            "ips": THREAT_IPS,
            "user": THREAT_USER,
            "host": THREAT_HOST,
            "alert_ids": {"ALT-101", "ALT-102"},
        }
