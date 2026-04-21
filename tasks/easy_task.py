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
    Correct responses: block_ip(target_ip) and/or flag_user(target_user).
    """

    TASK_ID = "easy_phishing_login"
    MAX_STEPS = 5
    DESCRIPTION = (
        "A phishing email was sent to a user from a malicious IP.  "
        "Shortly after, a successful VPN login from the same IP was detected "
        "with MFA bypassed.  Identify and mitigate the threat."
    )

    def __init__(self, **kwargs):
        # Allow RedAgent or custom_params to override the static defaults
        
        # Threat IP logic (Check if RedAgent mutated, OR if Live Intel fed real IPs)
        live_ips = kwargs.get("live_threat_ips", [])
        if kwargs.get("attacker_ip"):
            self.threat_ip = kwargs["attacker_ip"]
        elif live_ips:
            # Randomly pick one of the active live threat IPs if available
            import random
            self.threat_ip = random.choice(live_ips)
        else:
            self.threat_ip = THREAT_IP
            
        self.target_user = kwargs.get("target_user") or THREAT_USER

    def get_initial_observation(self, episode_id: str) -> SOCObservation:
        """Return the starting state of the easy task with dynamic substitutions."""
        import copy
        
        # Deepcopy the static baseline structure so we don't pollute global models
        p_evt = PHISHING_EVENT.model_copy(deep=True)
        m_evt = MALICIOUS_LOGIN_EVENT.model_copy(deep=True)
        b_evt = BENIGN_LOGIN_EVENT.model_copy(deep=True)
        
        p_alert = PHISHING_ALERT.model_copy(deep=True)
        i_alert = IMPOSSIBLE_TRAVEL_ALERT.model_copy(deep=True)
        
        # Override values with the potentially mutated strings
        p_evt.source_ip = self.threat_ip
        p_evt.user_id = self.target_user
        p_evt.raw_log = p_evt.raw_log.replace(THREAT_IP, self.threat_ip).replace(THREAT_USER, self.target_user)
        
        m_evt.source_ip = self.threat_ip
        m_evt.user_id = self.target_user
        m_evt.raw_log = m_evt.raw_log.replace(THREAT_IP, self.threat_ip).replace(THREAT_USER, self.target_user)
        
        p_alert.title = p_alert.title.replace(THREAT_USER, self.target_user)
        p_alert.description = p_alert.description.replace(THREAT_USER, self.target_user)
        
        i_alert.title = i_alert.title.replace(THREAT_USER, self.target_user)
        i_alert.description = i_alert.description.replace(THREAT_IP, self.threat_ip).replace(THREAT_USER, self.target_user)

        return SOCObservation(
            done=False,
            reward=0.0,
            metadata={"episode_id": episode_id},
            task_id=self.TASK_ID,
            step_number=0,
            timestamp=datetime(2024, 6, 15, 9, 18, 5),
            recent_events=[b_evt, p_evt, m_evt],
            active_alerts=[p_alert, i_alert],
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
        """Return dynamically-adjusted ground-truth targets for grading."""
        return {
            "ip": self.threat_ip,
            "user": self.target_user,
            "event_ids": THREAT_EVENTS,
            "alert_ids": {"ALT-001", "ALT-002"},
        }
