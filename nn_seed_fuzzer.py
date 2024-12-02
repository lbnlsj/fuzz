import os
import sys
import time
import signal
import subprocess
import multiprocessing
from pathlib import Path
import json
import plotly.graph_objects as go
import torch
import torch.nn as nn
import numpy as np
from collections import deque
import random


class FuzzFramework:
    def __init__(self, binary_path, input_dir, output_dir, timeout=24 * 3600):
        self.binary_path = binary_path
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.afl_path = "./AFLplusplus/afl-fuzz"
        self.coverage_data = []
        self.crash_data = []

    def run_afl(self):
        cmd = [
            self.afl_path,
            "-i", str(self.input_dir),
            "-o", str(self.output_dir),
            "-m", "none",
            "--",
            self.binary_path
        ]

        try:
            process = subprocess.Popen(cmd)
            start_time = time.time()

            while time.time() - start_time < self.timeout:
                if process.poll() is not None:
                    break
                self._collect_stats()
                time.sleep(60)

            process.terminate()

        except Exception as e:
            print(f"Error running AFL++: {e}")

    def _collect_stats(self):
        stats_file = self.output_dir / "default" / "fuzzer_stats"
        if not stats_file.exists():
            return

        with open(stats_file) as f:
            stats = {}
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    stats[key.strip()] = value.strip()

        self.coverage_data.append({
            "time": time.time(),
            "paths_total": int(stats.get("paths_total", 0)),
            "edge_coverage": int(stats.get("edges_found", 0))
        })

        self.crash_data.append({
            "time": time.time(),
            "unique_crashes": int(stats.get("unique_crashes", 0))
        })


class SeedEvaluator(nn.Module):
    def __init__(self, input_size=256):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)


class NeuralSeedSelector:
    def __init__(self, model_path=None):
        self.model = SeedEvaluator()
        self.buffer = deque(maxlen=10000)
        self.optimizer = torch.optim.Adam(self.model.parameters())
        self.criterion = nn.MSELoss()

    def preprocess_seed(self, seed_data):
        data = np.frombuffer(seed_data, dtype=np.uint8)
        if len(data) > 256:
            data = data[:256]
        else:
            data = np.pad(data, (0, 256 - len(data)))
        return torch.FloatTensor(data) / 255.0

    def evaluate_seed(self, seed_data):
        features = self.preprocess_seed(seed_data)
        with torch.no_grad():
            score = self.model(features)
        return score.item()

    def train(self, seed_data, reward):
        features = self.preprocess_seed(seed_data)
        self.buffer.append((features, reward))

        if len(self.buffer) < 32:
            return

        batch = random.sample(self.buffer, 32)
        features, rewards = zip(*batch)

        features = torch.stack(features)
        rewards = torch.FloatTensor(rewards)

        self.optimizer.zero_grad()
        predictions = self.model(features).squeeze()
        loss = self.criterion(predictions, rewards)
        loss.backward()
        self.optimizer.step()


class EnhancedFuzzFramework(FuzzFramework):
    def __init__(self, binary_path, input_dir, output_dir, timeout=24 * 3600):
        super().__init__(binary_path, input_dir, output_dir, timeout)
        self.seed_selector = NeuralSeedSelector()
        self.last_coverage = 0

    def _get_current_coverage(self):
        stats_file = self.output_dir / "enhanced" / "fuzzer_stats"
        if not stats_file.exists():
            return 0

        with open(stats_file) as f:
            for line in f:
                if "edges_found" in line:
                    return int(line.split(":")[-1].strip())
        return 0

    def run_enhanced_afl(self):
        env = os.environ.copy()

        cmd = [
            self.afl_path,
            "-i", str(self.input_dir),
            "-o", str(self.output_dir / "enhanced"),
            "-m", "none",
            "-D",
            "--",
            self.binary_path
        ]

        try:
            process = subprocess.Popen(cmd, env=env)
            start_time = time.time()

            while time.time() - start_time < self.timeout:
                if process.poll() is not None:
                    break

                queue_dir = self.output_dir / "enhanced" / "queue"
                if queue_dir.exists():
                    for seed_file in queue_dir.glob("id:*"):
                        with open(seed_file, "rb") as f:
                            seed_data = f.read()

                        current_coverage = self._get_current_coverage()
                        reward = (current_coverage - self.last_coverage) / max(1, current_coverage)
                        self.last_coverage = current_coverage

                        self.seed_selector.train(seed_data, reward)

                        score = self.seed_selector.evaluate_seed(seed_data)
                        if score < 0.5:
                            os.remove(seed_file)

                self._collect_enhanced_stats()
                time.sleep(60)

            process.terminate()

        except Exception as e:
            print(f"Error running enhanced AFL++: {e}")

    def _collect_enhanced_stats(self):
        stats_file = self.output_dir / "enhanced" / "fuzzer_stats"
        if not stats_file.exists():
            return

        with open(stats_file) as f:
            stats = {}
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    stats[key.strip()] = value.strip()

        self.coverage_data.append({
            "time": time.time(),
            "type": "enhanced",
            "paths_total": int(stats.get("paths_total", 0)),
            "edge_coverage": int(stats.get("edges_found", 0))
        })

        self.crash_data.append({
            "time": time.time(),
            "type": "enhanced",
            "unique_crashes": int(stats.get("unique_crashes", 0))
        })

    def generate_comparison_report(self):
        fig = go.Figure()

        base_data = [d for d in self.coverage_data if d.get("type") != "enhanced"]
        enhanced_data = [d for d in self.coverage_data if d.get("type") == "enhanced"]

        start_time = min(d["time"] for d in self.coverage_data)

        base_times = [(t["time"] - start_time) / 3600 for t in base_data]
        fig.add_trace(go.Scatter(
            x=base_times,
            y=[d["edge_coverage"] for d in base_data],
            name="Baseline Edge Coverage"
        ))

        enhanced_times = [(t["time"] - start_time) / 3600 for t in enhanced_data]
        fig.add_trace(go.Scatter(
            x=enhanced_times,
            y=[d["edge_coverage"] for d in enhanced_data],
            name="Enhanced Edge Coverage"
        ))

        fig.update_layout(
            title="Fuzzing Coverage Comparison",
            xaxis_title="Time (hours)",
            yaxis_title="Edge Coverage"
        )

        fig.write_html(self.output_dir / "comparison_report.html")

        with open(self.output_dir / "comparison_data.json", "w") as f:
            json.dump({
                "baseline": base_data,
                "enhanced": enhanced_data,
                "crashes": self.crash_data
            }, f, indent=2)


def main():
    test_binaries = [
        "./benchmark/exiv2",
        "./benchmark/mp4box",
        "./benchmark/objdump"
    ]

    for binary in test_binaries:
        print(f"Testing {binary}")

        fuzzer = EnhancedFuzzFramework(
            binary_path=binary,
            input_dir=f"./seeds/{Path(binary).name}",
            output_dir=f"./results/{Path(binary).name}"
        )

        fuzzer.run_afl()
        fuzzer.run_enhanced_afl()
        fuzzer.generate_comparison_report()


if __name__ == "__main__":
    main()