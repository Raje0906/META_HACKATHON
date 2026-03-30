"""
EASY TASK — Detect Phishing / Obvious Malicious Login
======================================================
Scenario:
  A corporate user receives a phishing email containing a credential-harvesting
  link.  Shortly after, a login from an unusual foreign IP succeeds — a clear
  account-takeover indicator.  The agent must detect either (or both) events
  and take appropriate action within 5 steps.

Difficulty: EASY
Max steps  : 5
Deterministic seed: 42
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from models import (
    ActionType, Alert, EventType, SecurityEvent, SOCObservation,
    SystemState, ThreatLevel,
)


# ---------------------------------------------------------------------------
# Static synthetic data (deterministic — never randomised)
# ---------------------------------------------------------------------------

PHISHING_EVENT = SecurityEvent(
    event_id="EVT-001",
    timestamp=datetime(2024, 6, 15, 9, 3, 12),
    event_type=EventType.PHISHING_EMAIL,
    source_ip="185.220.101.47",  # Known Tor exit node
    dest_ip=None,
    user_id="alice.chen",
    host_id="WORKSTATION-07",
    country="RU",
    details={
        "email_subject": "URGENT: Reset your corporate VPN password NOW",
        "sender": "it-support@corp-help-desk.ru",
        "link_url": "http://corp-vpn-reset.malicious.ru/login",
        "attachment": None,
        "spf_pass": False,
        "dkim_pass": False,
        "header_mismatch": True,
    },
    raw_log=(
        "2024-06-15T09:03:12Z [EMAIL-GATEWAY] INBOUND from=it-support@corp-help-desk.ru "
        "to=alice.chen@acmecorp.com subj='URGENT: Reset your corporate VPN password NOW' "
        "SPF=FAIL DKIM=FAIL link=http://corp-vpn-reset.malicious.ru/login"
    ),
)

MALICIOUS_LOGIN_EVENT = SecurityEvent(
    event_id="EVT-002",
    timestamp=datetime(2024, 6, 15, 9, 17, 44),
    event_type=EventType.LOGIN_SUCCESS,
    source_ip="185.220.101.47",
    dest_ip="10.0.0.5",
    user_id="alice.chen",
    host_id="VPN-GATEWAY-01",
    country="RU",
    details={
        "auth_method": "password",
        "usual_country": "US",
        "risk_signal": "impossible_travel",
        "time_since_phishing_email_min": 14,
        "mfa_bypassed": True,
        "session_id": "sess-8f2a1b",
    },
    raw_log=(
        "2024-06-15T09:17:44Z [VPN-AUTH] SUCCESS user=alice.chen "
        "src=185.220.101.47 (RU) dst=10.0.0.5 method=password MFA=BYPASSED"
    ),
)

BENIGN_LOGIN_EVENT = SecurityEvent(
    event_id="EVT-003",
    timestamp=datetime(2024, 6, 15, 9, 5, 0),
    event_type=EventType.LOGIN_SUCCESS,
    source_ip="203.0.113.55",
    dest_ip="10.0.0.5",
    user_id="bob.smith",
    host_id="VPN-GATEWAY-01",
    country="US",
    details={
        "auth_method": "mfa",
        "usual_country": "US",
        "risk_signal": None,
        "mfa_bypassed": False,
    },
    raw_log=(
        "2024-06-15T09:05:00Z [VPN-AUTH] SUCCESS user=bob.smith "
        "src=203.0.113.55 (US) dst=10.0.0.5 method=mfa MFA=OK"
    ),
)

PHISHING_ALERT = Alert(
    alert_id="ALT-001",
    title="Suspected Phishing Email Received by alice.chen",
    description=(
        "An inbound email to alice.chen failed SPF and DKIM checks.  "
        "The sender domain (corp-help-desk.ru) was registered 3 days ago.  "
        "The embedded link resolves to a known credential-harvesting domain."
    ),
    threat_level=ThreatLevel.HIGH,
    related_events=["EVT-001"],
    anomaly_score=0.91,
    triggered_at=datetime(2024, 6, 15, 9, 3, 30),
    mitre_tactic="Initial Access",
    mitre_technique="T1566.001",  # Spearphishing Link
)

IMPOSSIBLE_TRAVEL_ALERT = Alert(
    alert_id="ALT-002",
    title="Impossible Travel: alice.chen logged in from Russia",
    description=(
        "alice.chen successfully authenticated from IP 185.220.101.47 (RU) — "
        "14 minutes after receiving a phishing email from the same IP block.  "
        "MFA was bypassed, suggesting credential compromise."
    ),
    threat_level=ThreatLevel.CRITICAL,
    related_events=["EVT-001", "EVT-002"],
    anomaly_score=0.97,
    triggered_at=datetime(2024, 6, 15, 9, 18, 0),
    mitre_tactic="Initial Access",
    mitre_technique="T1078",  # Valid Accounts
)

# Ground truth: agent must block this IP and/or flag this user
THREAT_IP = "185.220.101.47"
THREAT_USER = "alice.chen"
THREAT_EVENTS = {"EVT-001", "EVT-002"}


class EasyTask:
    """
    Task definition for the EASY scenario.

    The environment exposes phishing + malicious-login events from step 0.
    Correct responses: block_ip("185.220.101.47") and/or flag_user("alice.chen").
    """

    TASK_ID = "easy_phishing_login"
    MAX_STEPS = 5
    DESCRIPTION = (
        "A phishing email was sent to alice.chen from a Russian IP.  "
        "Shortly after, a successful VPN login from the same IP was detected "
        "with MFA bypassed.  Identify and mitigate the threat."
    )

    def get_initial_observation(self, episode_id: str) -> SOCObservation:
        """Return the starting state of the easy task."""
        return SOCObservation(
            done=False,
            reward=0.0,
            metadata={"episode_id": episode_id},
            task_id=self.TASK_ID,
            step_number=0,
            timestamp=datetime(2024, 6, 15, 9, 18, 5),
            recent_events=[BENIGN_LOGIN_EVENT, PHISHING_EVENT, MALICIOUS_LOGIN_EVENT],
            active_alerts=[PHISHING_ALERT, IMPOSSIBLE_TRAVEL_ALERT],
            system_state=SystemState(
                active_connections=148,
                blocked_ips=[],
                flagged_users=[],
                isolated_hosts=[],
                open_incidents=2,
                risk_score=0.82,
            ),
            network_anomaly_score=0.84,
            hint=(
                "Pay close attention to the email gateway alert and the "
                "impossible-travel login from the same source IP."
            ),
        )

    def get_threat_targets(self) -> dict:
        """Return ground-truth targets for grading."""
        return {
            "ip": THREAT_IP,
            "user": THREAT_USER,
            "event_ids": THREAT_EVENTS,
            "alert_ids": {"ALT-001", "ALT-002"},
        }
