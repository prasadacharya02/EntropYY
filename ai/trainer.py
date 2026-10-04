# ============================================================
# ENTROPY - DQN Trainer
# ai\trainer.py
# ============================================================

import os
import sys
import json
import random
import numpy as np
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ai.dqn_model import DQNAgent, FeatureExtractor


def calculate_reward(action: int, true_label: int, threat_score: float) -> float:
    is_ransomware = (true_label == 1)

    if is_ransomware:
        if action == config.ACTION_TERMINATE_QUARANTINE:
            return 50.0
        elif action == config.ACTION_TERMINATE:
            return 40.0
        elif action == config.ACTION_ALERT:
            return 10.0
        else:
            return -100.0
    else:
        if action == config.ACTION_IGNORE:
            return 20.0
        elif action == config.ACTION_ALERT:
            return -10.0
        elif action == config.ACTION_TERMINATE:
            return -50.0
        else:
            return -80.0


class SecurityEnvironment:
    def __init__(self, training_data: list):
        self.training_data = list(training_data)
        self.feature_extractor = FeatureExtractor()
        self.current_sample = None
        self.step_count = 0

    def reset(self) -> np.ndarray:
        self.current_sample = random.choice(self.training_data)
        self.step_count = 0
        state = self.feature_extractor.extract_from_dict(self.current_sample)
        return state

    def step(self, action: int):
        self.step_count += 1
        true_label = self.current_sample.get('label', 0)
        threat_score = self._estimate_threat_score()

        reward = calculate_reward(action, true_label, threat_score)

        self.current_sample = random.choice(self.training_data)
        next_state = self.feature_extractor.extract_from_dict(self.current_sample)

        return next_state, reward, True

    def _estimate_threat_score(self) -> float:
        entropy = self.current_sample.get('entropy_score', 0)
        speed   = self.current_sample.get('files_per_sec', 0)
        delta   = self.current_sample.get('entropy_delta', 0)

        score = 0.0
        if entropy >= 7.5:
            score += 40
        if speed >= 5.0:
            score += 30
        if delta >= 2.0:
            score += 30

        return min(score, 100.0)


class DQNTrainer:
    def __init__(self, training_data: list):
        self.training_data = list(training_data)
        self.agent         = DQNAgent()
        self.env           = SecurityEnvironment(self.training_data)

    def train(self, num_episodes: int = 1500):
        print()
        print("=" * 60)
        print("  ENTROPY - DQN Training")
        print("=" * 60)
        print(f"  Training samples : {len(self.training_data)}")
        print(f"  Episodes         : {num_episodes}")
        print(f"  Device           : {self.agent.device}")
        print("=" * 60)
        print()

        episode_rewards = []
        correct_decisions = 0
        total_decisions = 0

        start_time = time.time()

        for episode in range(num_episodes):
            self.agent.episode = episode
            state = self.env.reset()

            action = self.agent.select_action(state, training=True)
            next_state, reward, done = self.env.step(action)

            self.agent.store_experience(state, action, reward, next_state, done)
            loss = self.agent.train_step()

            episode_rewards.append(reward)

            true_label = self.env.current_sample.get('label', 0)
            if self._is_correct_action(action, true_label):
                correct_decisions += 1
            total_decisions += 1

            if (episode + 1) % 250 == 0:
                recent_reward = np.mean(episode_rewards[-250:])
                accuracy = correct_decisions / max(total_decisions, 1)
                stats = self.agent.get_stats()

                print(f"  Episode {episode+1:5d}/{num_episodes} | "
                      f"Reward: {recent_reward:7.2f} | "
                      f"Accuracy: {accuracy:.1%} | "
                      f"Epsilon: {stats['epsilon']:.4f}")

                correct_decisions = 0
                total_decisions = 0

        elapsed = time.time() - start_time
        print()
        print("=" * 60)
        print(f"  Training Complete in {elapsed:.1f} seconds!")
        print("=" * 60)

        # Save model weights to ai/dqn_weights.pth
        self.agent.save()
        print("  Model weights successfully saved to ai/dqn_weights.pth!")
        return self.agent

    def _is_correct_action(self, action: int, true_label: int) -> bool:
        if true_label == 1:
            return action in [config.ACTION_TERMINATE, config.ACTION_TERMINATE_QUARANTINE]
        else:
            return action in [config.ACTION_IGNORE, config.ACTION_ALERT]


if __name__ == "__main__":
    training_file = os.path.join(config.TRAINING_DATA_DIR, "training_data.json")

    if not os.path.exists(training_file):
        print(f"ERROR: Training data not found at {training_file}")
        sys.exit(1)

    print(f"Loading training data from: {training_file}")
    with open(training_file, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    # Handle dictionary or list formats for training_data.json
    if isinstance(raw_data, dict):
        if 'samples' in raw_data:
            training_data = raw_data['samples']
        elif 'data' in raw_data:
            training_data = raw_data['data']
        else:
            lists = [v for v in raw_data.values() if isinstance(v, list)]
            training_data = lists[0] if lists else list(raw_data.values())
    else:
        training_data = raw_data

    print(f"Loaded {len(training_data)} samples.")

    normal_count = sum(1 for d in training_data if isinstance(d, dict) and d.get('label') == 0)
    ransom_count = sum(1 for d in training_data if isinstance(d, dict) and d.get('label') == 1)
    print(f"  Normal    : {normal_count}")
    print(f"  Ransomware: {ransom_count}")

    trainer = DQNTrainer(training_data)
    agent   = trainer.train(num_episodes=1500)