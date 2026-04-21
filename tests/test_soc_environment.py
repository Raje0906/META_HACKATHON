"""
SOC Simulator — pytest Test Suite
===================================
Validates environment correctness, reward function, and all three graders.
Run: pytest tests/ -v
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime
from models import ActionType, SOCAction, SOCState
from env.soc_environment import SOCEnvironment
from graders import EasyGrader, MediumGrader, HardGrader


# ─── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def env():
    return SOCEnvironment()


def make_state(actions, task_id="easy_phishing_login"):
    """Helper to build a SOCState for grader testing."""
    return SOCState(
        episode_id="test-ep-001",
        step_count=len(actions),
        task_id=task_id,
        agent_actions=actions,
        true_threats=["185.220.101.47", "alice.chen"],
        correct_detections=[],
        false_positives=0,
        false_negatives=0,
        total_reward=0.0,
        start_time=datetime.utcnow(),
    )


# ─── Environment API Tests ────────────────────────────────────────────────

class TestEnvironmentAPI:

    def test_reset_returns_observation(self, env):
        obs = env.reset(task_id="easy_phishing_login")
        assert obs is not None
        assert obs.task_id == "easy_phishing_login"
        assert obs.step_number == 0
        assert not obs.done

    def test_reset_all_tasks(self, env):
        for task_id in ["easy_phishing_login", "medium_brute_force_geo", "hard_apt_multistage"]:
            obs = env.reset(task_id=task_id)
            assert obs.task_id == task_id

    def test_invalid_task_raises(self, env):
        with pytest.raises(ValueError):
            env.reset(task_id="nonexistent_task")

    def test_step_before_reset_raises(self, env):
        with pytest.raises(RuntimeError):
            env.step(SOCAction(action_type=ActionType.IGNORE))

    def test_step_returns_observation(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(action_type=ActionType.IGNORE))
        assert obs is not None
        assert hasattr(obs, "reward")
        assert hasattr(obs, "done")

    def test_episode_ends_at_max_steps(self, env):
        env.reset(task_id="easy_phishing_login")  # max_steps=5
        obs = None
        for _ in range(6):
            obs = env.step(SOCAction(action_type=ActionType.IGNORE))
            if obs.done:
                break
        assert obs.done

    def test_state_property(self, env):
        env.reset(task_id="easy_phishing_login")
        assert env.state is not None
        assert env.state.task_id == "easy_phishing_login"
        assert env.state.step_count == 0

    def test_step_increments_step_count(self, env):
        env.reset(task_id="easy_phishing_login")
        env.step(SOCAction(action_type=ActionType.IGNORE))
        assert env.state.step_count == 1


# ─── Reward Function Tests ────────────────────────────────────────────────

class TestRewardFunction:

    def test_correct_block_ip_positive_reward(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(
            action_type=ActionType.BLOCK_IP,
            target="185.220.101.47"
        ))
        assert obs.reward > 0

    def test_wrong_block_ip_negative_reward(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(
            action_type=ActionType.BLOCK_IP,
            target="8.8.8.8"  # Google DNS — not a threat
        ))
        assert obs.reward < 0

    def test_correct_flag_user_positive_reward(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(
            action_type=ActionType.FLAG_USER,
            target="alice.chen"
        ))
        assert obs.reward > 0

    def test_wrong_flag_user_negative_reward(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(
            action_type=ActionType.FLAG_USER,
            target="bob.smith"  # Benign user
        ))
        assert obs.reward < 0

    def test_duplicate_action_penalty(self, env):
        env.reset(task_id="easy_phishing_login")
        env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"))
        obs2 = env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"))
        assert obs2.reward < 0  # Redundant action penalty

    def test_escalate_with_active_threat_positive(self, env):
        env.reset(task_id="easy_phishing_login")
        obs = env.step(SOCAction(action_type=ActionType.ESCALATE_ALERT))
        assert obs.reward > 0


# ─── Easy Grader Tests ─────────────────────────────────────────────────────

class TestEasyGrader:

    def test_perfect_score(self):
        grader = EasyGrader()
        actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"},
            {"action_type": ActionType.FLAG_USER, "target": "alice.chen"},
            {"action_type": ActionType.ESCALATE_ALERT, "target": None},
        ]
        state = make_state(actions)
        state.agent_actions = actions
        score = grader.grade(state)
        assert score >= 0.80  # Should be at least 0.8 (0.35+0.35+0.10)

    def test_zero_score_no_action(self):
        grader = EasyGrader()
        state = make_state([])
        score = grader.grade(state)
        assert score == 0.0

    def test_partial_score_ip_only(self):
        grader = EasyGrader()
        actions = [{"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"}]
        state = make_state(actions)
        state.agent_actions = actions
        score = grader.grade(state)
        assert 0.30 <= score <= 0.55  # IP blocked only

    def test_false_positive_reduces_score(self):
        grader = EasyGrader()
        base_actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"},
            {"action_type": ActionType.FLAG_USER, "target": "alice.chen"},
        ]
        fp_actions = base_actions + [
            {"action_type": ActionType.BLOCK_IP, "target": "1.1.1.1"},   # FP
            {"action_type": ActionType.BLOCK_IP, "target": "8.8.8.8"},   # FP
        ]
        state_base = make_state(base_actions)
        state_base.agent_actions = base_actions
        state_fp = make_state(fp_actions)
        state_fp.agent_actions = fp_actions
        state_fp.false_positives = 2

        assert grader.grade(state_fp) < grader.grade(state_base)

    def test_score_clamped_between_0_and_1(self):
        grader = EasyGrader()
        actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"},
            {"action_type": ActionType.FLAG_USER, "target": "alice.chen"},
            {"action_type": ActionType.ESCALATE_ALERT, "target": None},
        ]
        s = make_state(actions)
        s.agent_actions = actions
        score = grader.grade(s)
        assert 0.0 <= score <= 1.0

    def test_early_detection_bonus(self):
        grader = EasyGrader()
        actions_early = [
            {"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"},
        ]
        actions_late = [
            {"action_type": ActionType.IGNORE, "target": None},
            {"action_type": ActionType.IGNORE, "target": None},
            {"action_type": ActionType.IGNORE, "target": None},
            {"action_type": ActionType.BLOCK_IP, "target": "185.220.101.47"},
        ]
        s_early = make_state(actions_early)
        s_early.agent_actions = actions_early
        s_late = make_state(actions_late)
        s_late.agent_actions = actions_late

        assert grader.grade(s_early) >= grader.grade(s_late)


# ─── Medium Grader Tests ───────────────────────────────────────────────────

class TestMediumGrader:

    def test_perfect_score(self):
        grader = MediumGrader()
        actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "45.142.212.100"},
            {"action_type": ActionType.BLOCK_IP, "target": "91.108.56.22"},
            {"action_type": ActionType.FLAG_USER, "target": "finance.admin"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "FINANCE-SRV-01"},
        ]
        s = make_state(actions, task_id="medium_brute_force_geo")
        s.agent_actions = actions
        score = grader.grade(s)
        assert score >= 0.85

    def test_red_herring_penalty(self):
        grader = MediumGrader()
        base_actions = [{"action_type": ActionType.BLOCK_IP, "target": "45.142.212.100"}]
        rh_actions = base_actions + [
            {"action_type": ActionType.BLOCK_IP, "target": "77.88.55.88"},  # Red herring
        ]
        s1 = make_state(base_actions, "medium_brute_force_geo")
        s1.agent_actions = base_actions
        s2 = make_state(rh_actions, "medium_brute_force_geo")
        s2.agent_actions = rh_actions
        s2.false_positives = 1

        assert grader.grade(s1) > grader.grade(s2)


# ─── Hard Grader Tests ─────────────────────────────────────────────────────

class TestHardGrader:

    def test_perfect_score(self):
        grader = HardGrader()
        actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "198.51.100.77"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "WEB-SRV-01"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "FINANCE-DB-01"},
            {"action_type": ActionType.FLAG_USER, "target": "backup-svc"},
            {"action_type": ActionType.ESCALATE_ALERT, "target": None},
        ]
        s = make_state(actions, task_id="hard_apt_multistage")
        s.agent_actions = actions
        s.attack_stages_detected = ["reconnaissance", "initial_access", "lateral_movement", "exfiltration"]
        score = grader.grade(s)
        assert score >= 0.90

    def test_partial_only_recon(self):
        grader = HardGrader()
        actions = [{"action_type": ActionType.BLOCK_IP, "target": "198.51.100.77"}]
        s = make_state(actions, "hard_apt_multistage")
        s.agent_actions = actions
        score = grader.grade(s)
        assert 0.10 <= score <= 0.30

    def test_stage_ordering_bonus(self):
        grader = HardGrader()
        in_order = [
            {"action_type": ActionType.BLOCK_IP, "target": "198.51.100.77"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "WEB-SRV-01"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "FINANCE-DB-01"},
            {"action_type": ActionType.ESCALATE_ALERT, "target": None},
        ]
        out_of_order = [
            {"action_type": ActionType.ESCALATE_ALERT, "target": None},
            {"action_type": ActionType.ISOLATE_HOST, "target": "FINANCE-DB-01"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "WEB-SRV-01"},
            {"action_type": ActionType.BLOCK_IP, "target": "198.51.100.77"},
        ]
        s1 = make_state(in_order, "hard_apt_multistage")
        s1.agent_actions = in_order
        s2 = make_state(out_of_order, "hard_apt_multistage")
        s2.agent_actions = out_of_order

        # Ordered detection should score higher or equal
        assert grader.grade(s1) >= grader.grade(s2)

    def test_score_is_deterministic(self):
        """Same inputs must always produce same score."""
        grader = HardGrader()
        actions = [
            {"action_type": ActionType.BLOCK_IP, "target": "198.51.100.77"},
            {"action_type": ActionType.ISOLATE_HOST, "target": "WEB-SRV-01"},
        ]
        s = make_state(actions, "hard_apt_multistage")
        s.agent_actions = actions
        score1 = grader.grade(s)
        score2 = grader.grade(s)
        assert score1 == score2


# ─── Integration Test ──────────────────────────────────────────────────────

class TestFullEpisode:

    def test_easy_full_episode_optimal(self, env):
        """Run optimal actions for easy task and check final score >= 0.8."""
        env.reset(task_id="easy_phishing_login")
        env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="185.220.101.47"))
        env.step(SOCAction(action_type=ActionType.FLAG_USER, target="alice.chen"))
        env.step(SOCAction(action_type=ActionType.ESCALATE_ALERT))
        score = env.get_final_score()
        assert score >= 0.80

    def test_medium_full_episode(self, env):
        """Run optimal actions for medium task."""
        env.reset(task_id="medium_brute_force_geo")
        env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="45.142.212.100"))
        env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="91.108.56.22"))
        env.step(SOCAction(action_type=ActionType.FLAG_USER, target="finance.admin"))
        env.step(SOCAction(action_type=ActionType.ISOLATE_HOST, target="FINANCE-SRV-01"))
        score = env.get_final_score()
        assert score >= 0.80

    def test_hard_full_episode(self, env):
        """Run optimal actions for hard task."""
        env.reset(task_id="hard_apt_multistage")
        env.step(SOCAction(action_type=ActionType.BLOCK_IP, target="198.51.100.77"))
        env.step(SOCAction(action_type=ActionType.ISOLATE_HOST, target="WEB-SRV-01"))
        env.step(SOCAction(action_type=ActionType.ISOLATE_HOST, target="FINANCE-DB-01"))
        env.step(SOCAction(action_type=ActionType.FLAG_USER, target="backup-svc"))
        env.step(SOCAction(action_type=ActionType.ESCALATE_ALERT))
        score = env.get_final_score()
        assert score >= 0.80

    def test_all_task_scores_in_range(self, env):
        """Ensure all graders return scores in [0, 1]."""
        tasks = [
            ("easy_phishing_login", [
                SOCAction(action_type=ActionType.IGNORE),
            ]),
            ("medium_brute_force_geo", [
                SOCAction(action_type=ActionType.IGNORE),
            ]),
            ("hard_apt_multistage", [
                SOCAction(action_type=ActionType.IGNORE),
            ]),
        ]
        for task_id, actions in tasks:
            env.reset(task_id=task_id)
            for a in actions:
                env.step(a)
            score = env.get_final_score()
            assert 0.0 <= score <= 1.0, f"Score out of range for {task_id}: {score}"

# ─── Upgrades Integration Tests ─────────────────────────────────────────────

from env.red_agent import RedAgent, BlueMemory
from env.dynamic_input import DynamicInputPipeline
from env.schema_drift import SchemaDriftEngine

class TestUpgrades:
    def test_red_agent_mutation(self):
        agent = RedAgent(seed=42)
        blue_mem = BlueMemory(blocked_ips={"1.2.3.4"}, flagged_users={"bob"}, isolated_hosts=set(), episode_score=0.8)
        scenario = agent.get_mutated_scenario("easy_phishing_login", blue_mem)
        assert "attacker_ip" in scenario
        assert scenario["attacker_ip"] != "185.220.101.47"

    def test_dynamic_input_pipeline_adapt_difficulty(self):
        pipeline = DynamicInputPipeline()
        pipeline.record_episode_score(0.2)
        pipeline.record_episode_score(0.2)
        diff = pipeline.adapt_difficulty()
        assert diff["difficulty_level"] == "easy"
        
        # Elevate scores
        for _ in range(5):
            pipeline.record_episode_score(0.9)
        diff = pipeline.adapt_difficulty()
        assert diff["difficulty_level"] == "hard"

    def test_schema_drift_engine(self):
        engine = SchemaDriftEngine(seed=42)
        events = [{"event_type": "phishing_email", "source_ip": "1.2.3.4", "user_id": "alice"}]
        
        # Force a drift
        engine._current_version = "v2"
        drifted = engine.apply_drift(events)
        
        assert "evt_category" in drifted[0]
        assert "src_addr" in drifted[0]
        assert "username" in drifted[0]
        assert "source_ip" not in drifted[0]
