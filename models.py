"""
SOC Simulator - Core Pydantic Models
=====================================
Defines the typed data structures for the AI Cybersecurity Incident Response
Environment: Action, Observation, and State used throughout the OpenEnv interface.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """All possible analyst actions in the SOC."""
    BLOCK_IP = "block_ip"
    FLAG_USER = "flag_user"
    ISOLATE_HOST = "isolate_host"
    IGNORE = "ignore"
    ESCALATE_ALERT = "escalate_alert"


class ThreatLevel(str, Enum):
    """Severity classification for security events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventType(str, Enum):
    """Types of security events seen in logs."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    NETWORK_SCAN = "network_scan"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfiltration"
    PHISHING_EMAIL = "phishing_email"
    MALWARE_EXEC = "malware_execution"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PORT_SCAN = "port_scan"
    FILE_ACCESS = "file_access"
    DNS_QUERY = "dns_query"


# ---------------------------------------------------------------------------
# Action Model
# ---------------------------------------------------------------------------

class SOCAction(BaseModel):
    """
    A structured analyst action in the SOC environment.

    The agent must choose one action per step.  Each action type requires
    specific parameters — unrecognised parameters are silently ignored.

    Examples
    --------
    >>> SOCAction(action_type=ActionType.BLOCK_IP, target="192.168.1.42")
    >>> SOCAction(action_type=ActionType.FLAG_USER, target="jdoe")
    >>> SOCAction(action_type=ActionType.ESCALATE_ALERT)
    """

    action_type: ActionType = Field(
        ...,
        description="The type of response action to take.",
    )
    target: Optional[str] = Field(
        None,
        description="IP address, user_id, or host_id depending on action_type.",
    )
    reason: Optional[str] = Field(
        None,
        description="Optional free-text justification for the action (logged for audit).",
    )
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Agent's confidence score for this action (0-1).",
    )
    step_taken_at: Optional[datetime] = Field(
        None,
        description="Timestamp when the action was decided (set by environment).",
    )


# ---------------------------------------------------------------------------
# Security Event (sub-model used inside Observation)
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    """A single structured security log entry."""

    event_id: str = Field(..., description="Unique event identifier.")
    timestamp: datetime = Field(..., description="When the event occurred.")
    event_type: EventType = Field(..., description="Category of the security event.")
    source_ip: Optional[str] = Field(None, description="Source IP address.")
    dest_ip: Optional[str] = Field(None, description="Destination IP address (if applicable).")
    user_id: Optional[str] = Field(None, description="User associated with the event.")
    host_id: Optional[str] = Field(None, description="Host / endpoint involved.")
    country: Optional[str] = Field(None, description="Geo-location of source IP.")
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured metadata about the event.",
    )
    raw_log: Optional[str] = Field(None, description="Raw log line as it would appear in SIEM.")


class Alert(BaseModel):
    """A SIEM-generated alert derived from one or more security events."""

    alert_id: str = Field(..., description="Unique alert identifier.")
    title: str = Field(..., description="Human-readable alert title.")
    description: str = Field(..., description="Detailed explanation of the alert.")
    threat_level: ThreatLevel = Field(..., description="Assessed severity.")
    related_events: List[str] = Field(
        default_factory=list,
        description="Event IDs that triggered this alert.",
    )
    anomaly_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="ML anomaly score (0 = benign, 1 = highly suspicious).",
    )
    triggered_at: datetime = Field(..., description="When alert was generated.")
    mitre_tactic: Optional[str] = Field(
        None,
        description="MITRE ATT&CK tactic this alert maps to.",
    )
    mitre_technique: Optional[str] = Field(
        None,
        description="MITRE ATT&CK technique ID (e.g., T1078).",
    )


class SystemState(BaseModel):
    """Snapshot of the current infrastructure state."""

    active_connections: int = Field(0, description="Number of active network connections.")
    blocked_ips: List[str] = Field(default_factory=list, description="Currently blocked IPs.")
    flagged_users: List[str] = Field(default_factory=list, description="Currently flagged users.")
    isolated_hosts: List[str] = Field(default_factory=list, description="Currently isolated hosts.")
    open_incidents: int = Field(0, description="Number of open incidents.")
    risk_score: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Overall network risk score (0 = safe, 1 = critical).",
    )


# ---------------------------------------------------------------------------
# Observation Model
# ---------------------------------------------------------------------------

class SOCObservation(BaseModel):
    """
    The observation returned to the agent at each environment step.

    Mirrors what a real SOC analyst would see on their dashboard:
    recent logs, active alerts, anomaly scores, and system posture.
    """

    # Core OpenEnv fields (required by framework)
    done: bool = Field(False, description="Whether the episode has ended.")
    reward: float = Field(0.0, description="Reward received for the last action.")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # SOC-specific fields
    task_id: str = Field(..., description="Current task identifier.")
    step_number: int = Field(0, description="Current step within the episode.")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    recent_events: List[Any] = Field(
        default_factory=list,
        description="Last N security log events visible to the agent. Format may drift.",
    )
    active_alerts: List[Alert] = Field(
        default_factory=list,
        description="Currently active SIEM alerts requiring analyst attention.",
    )
    system_state: SystemState = Field(
        default_factory=SystemState,
        description="Current infrastructure posture.",
    )
    network_anomaly_score: float = Field(
        0.0,
        ge=0.0,
        le=1.0,
        description="Network-wide anomaly score from behavioral analytics.",
    )
    attack_stage: Optional[str] = Field(
        None,
        description="Detected attack stage for multi-stage scenarios (if any).",
    )
    hint: Optional[str] = Field(
        None,
        description="Optional contextual hint (used in easy tasks).",
    )
    schema_version: str = Field(
        "v1",
        description="Current SIEM log schema version (v1, v2, v3). Used to identify drift.",
    )


# ---------------------------------------------------------------------------
# State Model (internal episode tracking)
# ---------------------------------------------------------------------------

class SOCState(BaseModel):
    """Internal environment state — tracks episode progress and scoring."""

    episode_id: str = Field(..., description="Unique episode identifier.")
    step_count: int = Field(0, description="Number of steps taken so far.")
    task_id: str = Field(..., description="Active task (easy / medium / hard).")
    task_completed: bool = Field(False)
    true_threats: List[str] = Field(
        default_factory=list,
        description="Ground-truth threat IDs the agent must identify.",
    )
    agent_actions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Full action history for grading.",
    )
    correct_detections: List[str] = Field(default_factory=list)
    false_positives: int = Field(0)
    false_negatives: int = Field(0)
    total_reward: float = Field(0.0)
    start_time: datetime = Field(default_factory=datetime.utcnow)
    attack_stages_detected: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Custom Parameters (Source C — Runtime Overrides for POST /reset)
# ---------------------------------------------------------------------------

class CustomParams(BaseModel):
    """
    Optional runtime overrides for the POST /reset request body.

    All fields are optional with safe defaults (None / False).
    When a field is provided, it overrides the corresponding scenario default.

    Examples
    --------
    >>> CustomParams(attacker_ip="198.51.100.99", enable_red_agent=True)
    >>> CustomParams(target_user="custom.user", attack_intensity=0.8)
    """

    attacker_ip: Optional[str] = Field(
        None,
        description=(
            "Override the primary attacker source IP used in the scenario. "
            "Should be a valid IPv4 address string."
        ),
    )
    target_user: Optional[str] = Field(
        None,
        description="Override the targeted / compromised username in the scenario.",
    )
    attack_intensity: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description=(
            "Override scenario attack intensity on a [0, 1] scale. "
            "Higher values increase event volume and anomaly scores."
        ),
    )
    enable_red_agent: Optional[bool] = Field(
        True,
        description=(
            "If True, activate the RedAgent adaptive adversary which mutates "
            "the scenario based on the blue agent's previous-episode actions."
        ),
    )
    use_live_threat_intel: Optional[bool] = Field(
        True,
        description=(
            "If True, fetch fresh attacker IPs from live threat intel feeds "
            "(URLhaus + Feodo Tracker) instead of using static scenario defaults."
        ),
    )
    enable_schema_drift: Optional[bool] = Field(
        True,
        description=(
            "If True, activate the SchemaDriftEngine which randomly mutates "
            "log field names every 10 steps to test agent adaptability."
        ),
    )
