"""
DynamicInputPipeline — Three-Source Dynamic Scenario Input
===========================================================
Provides a unified interface for three sources of dynamic input that drive
scenario variation in the SOC Simulator:

Source A — Live Threat Intel Feed
    Fetches malicious IPs from URLhaus and Feodo Tracker (both free, no auth).
    Results are cached for 1 hour.  Falls back to hardcoded IPs on failure.

Source B — Performance-Based Difficulty Adaptation
    Tracks blue agent's rolling average score over the last 5 episodes and
    returns difficulty adjustment parameters accordingly.

Source C — Runtime Custom Parameters
    Accepts per-request overrides (attacker_ip, target_user, attack_intensity,
    enable_red_agent, use_live_threat_intel) that merge on top of scenario
    defaults.

Usage
-----
pipeline = DynamicInputPipeline()

# Source A
threat_ips = pipeline.get_live_threat_ips()

# Source B
params = pipeline.adapt_difficulty([0.3, 0.5, 0.6, 0.45, 0.55])

# Source C — typically called by the server layer
merged = pipeline.merge_custom_params(base_scenario_params, custom_params_dict)
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
FEODO_BLOCKLIST_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
)

CACHE_TTL_SECONDS = 3600  # 1 hour

# Hardcoded fallback — realistic-looking attacker IPs from documentation ranges
FALLBACK_THREAT_IPS: List[str] = [
    "198.51.100.10",
    "198.51.100.35",
    "198.51.100.77",
    "203.0.113.5",
    "203.0.113.42",
    "203.0.113.99",
    "198.51.100.120",
    "203.0.113.150",
]

# Difficulty adaptation thresholds
LOW_SCORE_THRESHOLD = 0.40
HIGH_SCORE_THRESHOLD = 0.75


# ---------------------------------------------------------------------------
# DynamicInputPipeline
# ---------------------------------------------------------------------------


class DynamicInputPipeline:
    """
    Unified pipeline for three sources of dynamic scenario input.

    Thread Safety
    -------------
    The class keeps a simple in-memory cache.  For single-threaded or
    asyncio-based usage (FastAPI) this is safe.  For multi-process deployment
    consider an external cache (Redis).
    """

    def __init__(
        self,
        cache_ttl: int = CACHE_TTL_SECONDS,
        http_timeout: int = 10,
    ) -> None:
        """
        Parameters
        ----------
        cache_ttl : int
            Number of seconds to cache threat-intel results (default 3600).
        http_timeout : int
            HTTP request timeout in seconds (default 10).
        """
        self._cache_ttl = cache_ttl
        self._http_timeout = http_timeout

        # Source A — threat intel cache
        self._threat_ip_cache: List[str] = []
        self._cache_fetched_at: float = 0.0  # epoch seconds

        # Source B — episode score history (stored internally)
        self._score_history: List[float] = []

    # =========================================================================
    # SOURCE A — Live Threat Intel
    # =========================================================================

    def get_live_threat_ips(self) -> List[str]:
        """
        Return a deduplicated list of malicious IPs from live threat feeds.

        Sources:
        - URLhaus API (recent malware URLs → extract host IPs)
        - Feodo Tracker IP blocklist (JSON)

        Results are cached for ``cache_ttl`` seconds.  On any network /
        parsing failure the method falls back to ``FALLBACK_THREAT_IPS``.

        Returns
        -------
        List[str]
            Deduplicated list of malicious IP strings.
        """
        now = time.monotonic()
        if (
            self._threat_ip_cache
            and (now - self._cache_fetched_at) < self._cache_ttl
        ):
            logger.debug("Returning cached threat IPs (%d entries).", len(self._threat_ip_cache))
            return list(self._threat_ip_cache)

        ips: List[str] = []

        # ── URLhaus ──────────────────────────────────────────────────────────
        try:
            resp = requests.post(
                URLHAUS_API_URL,
                data={"limit": 100},
                timeout=self._http_timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            for url_entry in payload.get("urls", []):
                host = url_entry.get("host", "")
                # Only keep plain IP addresses (not domain names)
                if host and self._is_ipv4(host):
                    ips.append(host)
            logger.info("URLhaus: fetched %d malicious IPs.", len(ips))
        except Exception as exc:  # noqa: BLE001
            logger.debug("URLhaus fetch failed (typically requires API key now) — %s", exc)

        # ── Feodo Tracker ────────────────────────────────────────────────────
        try:
            resp = requests.get(
                FEODO_BLOCKLIST_URL,
                timeout=self._http_timeout,
            )
            resp.raise_for_status()
            entries = resp.json()
            feodo_ips = [
                e.get("ip_address", "")
                for e in entries
                if isinstance(e, dict) and e.get("ip_address")
            ]
            ips.extend(feodo_ips)
            logger.info("FeodoTracker: fetched %d malicious IPs.", len(feodo_ips))
        except Exception as exc:  # noqa: BLE001
            logger.warning("FeodoTracker fetch failed — %s", exc)

        # Deduplicate + validate
        unique_ips = list(dict.fromkeys(ip for ip in ips if self._is_ipv4(ip)))

        if unique_ips:
            self._threat_ip_cache = unique_ips
            self._cache_fetched_at = now
            return list(unique_ips)

        # All fetches failed — return fallback
        logger.warning(
            "All threat intel sources failed.  Using fallback IP list (%d entries).",
            len(FALLBACK_THREAT_IPS),
        )
        return list(FALLBACK_THREAT_IPS)

    def get_threat_intel_summary(self) -> Dict[str, Any]:
        """
        Return metadata about the current threat intel cache state.

        Returns
        -------
        dict with keys: cached_ip_count, cache_age_seconds, cache_valid,
                        sample_ips (first 5)
        """
        now = time.monotonic()
        age = now - self._cache_fetched_at if self._cache_fetched_at > 0 else None
        return {
            "cached_ip_count": len(self._threat_ip_cache),
            "cache_age_seconds": round(age, 1) if age is not None else None,
            "cache_valid": bool(
                self._threat_ip_cache and age is not None and age < self._cache_ttl
            ),
            "sample_ips": self._threat_ip_cache[:5],
        }

    # =========================================================================
    # SOURCE B — Performance-Based Difficulty Adaptation
    # =========================================================================

    def adapt_difficulty(
        self, score_history: Optional[List[float]] = None
    ) -> Dict[str, Any]:
        """
        Compute difficulty adjustment parameters based on rolling avg score.

        Parameters
        ----------
        score_history : List[float], optional
            Episode scores to use.  If None, uses the internally tracked
            history (updated via ``record_episode_score``).  Uses the last 5
            scores from the provided list.

        Returns
        -------
        dict
            Keys:
            - ``difficulty_level`` : "easy" | "medium" | "hard"
            - ``rolling_avg_score`` : float
            - ``num_attack_events`` : int  (suggested event count)
            - ``inject_decoy_alert`` : bool
            - ``add_lateral_movement`` : bool
            - ``concurrent_attack_streams`` : int
            - ``use_obvious_malicious_ips`` : bool
            - ``rationale`` : str
        """
        history = score_history if score_history is not None else self._score_history
        recent = history[-5:] if len(history) >= 5 else history

        avg = sum(recent) / len(recent) if recent else 0.0

        params: Dict[str, Any] = {
            "rolling_avg_score": round(avg, 4),
            "episodes_considered": len(recent),
        }

        if avg < LOW_SCORE_THRESHOLD:
            # Blue agent struggling — make it easier
            params.update(
                {
                    "difficulty_level": "easy",
                    "num_attack_events": 3,
                    "inject_decoy_alert": False,
                    "add_lateral_movement": False,
                    "concurrent_attack_streams": 1,
                    "use_obvious_malicious_ips": True,
                    "rationale": (
                        f"Rolling avg score {avg:.2f} < {LOW_SCORE_THRESHOLD}. "
                        "Reduced event count and obvious attacker IPs to lower difficulty."
                    ),
                }
            )

        elif LOW_SCORE_THRESHOLD <= avg <= HIGH_SCORE_THRESHOLD:
            # Blue agent performing adequately — maintain current difficulty
            params.update(
                {
                    "difficulty_level": "medium",
                    "num_attack_events": 6,
                    "inject_decoy_alert": False,
                    "add_lateral_movement": False,
                    "concurrent_attack_streams": 1,
                    "use_obvious_malicious_ips": False,
                    "rationale": (
                        f"Rolling avg score {avg:.2f} in [{LOW_SCORE_THRESHOLD}, "
                        f"{HIGH_SCORE_THRESHOLD}]. Maintaining current difficulty."
                    ),
                }
            )

        else:
            # Blue agent excelling — escalate challenge
            params.update(
                {
                    "difficulty_level": "hard",
                    "num_attack_events": 10,
                    "inject_decoy_alert": True,       # A benign IP that looks suspicious
                    "add_lateral_movement": True,     # Add a new lateral movement hop
                    "concurrent_attack_streams": 3,   # Multiple simultaneous attacker IPs
                    "use_obvious_malicious_ips": False,
                    "rationale": (
                        f"Rolling avg score {avg:.2f} > {HIGH_SCORE_THRESHOLD}. "
                        "Injecting decoy alert, adding lateral movement step, "
                        "and increasing concurrent attack streams."
                    ),
                }
            )

        return params

    def record_episode_score(self, score: float) -> None:
        """
        Append an episode's final score to the internal history for
        subsequent ``adapt_difficulty()`` calls.

        Parameters
        ----------
        score : float
            Final grader score in [0, 1].
        """
        self._score_history.append(score)
        # Keep only last 20 to avoid unbounded growth
        if len(self._score_history) > 20:
            self._score_history = self._score_history[-20:]

    @property
    def score_history(self) -> List[float]:
        """Read-only copy of the internal score history."""
        return list(self._score_history)

    # =========================================================================
    # SOURCE C — Runtime Custom Parameter Merging
    # =========================================================================

    def merge_custom_params(
        self,
        base_params: Dict[str, Any],
        custom_params: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Merge runtime custom parameters on top of base scenario defaults.

        Only keys present in ``custom_params`` with non-None values will
        override the base.  All other base keys are preserved.

        Parameters
        ----------
        base_params : dict
            The scenario's default parameters.
        custom_params : dict or None
            Overrides provided at runtime (from the POST /reset body).

        Returns
        -------
        dict
            Merged parameter dict with custom overrides applied.
        """
        merged = dict(base_params)
        if not custom_params:
            return merged

        for key, value in custom_params.items():
            if value is not None:
                merged[key] = value

        return merged

    # =========================================================================
    # Helpers
    # =========================================================================

    @staticmethod
    def _is_ipv4(s: str) -> bool:
        """Return True if ``s`` looks like a valid IPv4 address."""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
