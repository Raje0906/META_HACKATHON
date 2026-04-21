"""
Schema Drift Engine (Patronus AI Bonus)
=======================================
Simulates real-world SIEM schema changes without warning to test if the 
autonomous agent can adapt to different key names for standard fields.

Baseline (v1) -> source_ip | target_user | event_type
Drift (v2)    -> src_addr  | username    | evt_category
Drift (v3)    -> remote_ip | account_name| log_type
"""

from __future__ import annotations

import random
from copy import deepcopy
from typing import Any, Dict, List, Optional


class SchemaDriftEngine:
    """
    Randomly mutates SecurityEvent schemas every 10 steps.
    """

    VERSIONS = ["v1", "v2", "v3"]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._current_version = "v1"

    @property
    def current_version(self) -> str:
        return self._current_version

    def maybe_drift(self, step_number: int) -> None:
        """
        Check if we should drift the schema.
        Drifts happen every 10 steps, or at episode start (step 0).
        """
        if step_number == 0 or (step_number > 0 and step_number % 10 == 0):
            self._current_version = self._rng.choice(self.VERSIONS)

    def apply_drift(self, recent_events: List[Any]) -> List[Any]:
        """
        Takes a list of SecurityEvents and transforms them into dictionaries
        matching the current schema version.
        
        If version is v1, returns the objects functionally identical (as dicts).
        """
        drifted = []
        for event in recent_events:
            # We convert to a dict if it is a Pydantic model
            if hasattr(event, "model_dump"):
                evt_dict = event.model_dump(exclude_none=True)
            else:
                evt_dict = deepcopy(event)

            # Map the fields if drifting
            if self._current_version == "v2":
                self._map_field(evt_dict, "source_ip", "src_addr")
                self._map_field(evt_dict, "user_id", "username")
                self._map_field(evt_dict, "event_type", "evt_category")
            elif self._current_version == "v3":
                self._map_field(evt_dict, "source_ip", "remote_ip")
                self._map_field(evt_dict, "user_id", "account_name")
                self._map_field(evt_dict, "event_type", "log_type")

            drifted.append(evt_dict)

        return drifted

    @staticmethod
    def _map_field(evt_dict: Dict[str, Any], old_key: str, new_key: str) -> None:
        """Renames a key in a dictionary if it exists."""
        if old_key in evt_dict:
            evt_dict[new_key] = evt_dict.pop(old_key)
