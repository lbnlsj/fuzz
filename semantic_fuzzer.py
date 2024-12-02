import os
import sys
import time
import signal
import subprocess
import multiprocessing
from pathlib import Path
import json
import plotly.graph_objects as go
import random
from typing import List, Dict


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


class SemanticMutator:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.interesting_bytes = [0x00, 0xff, 0x7f, 0x80]

    def get_mutation_points(self, input_data: bytes) -> List[int]:
        """基于启发式规则确定变异位置"""
        points = []

        # 识别可能的长度字段和特殊字节
        for i in range(len(input_data) - 4):
            value = int.from_bytes(input_data[i:i + 4], byteorder='big')
            if value in self.interesting_bytes:
                points.append(i)
            if value < len(input_data) and value > 0:  # 可能是长度字段
                points.append(i)

        # 识别文件头部和结构边界
        points.extend([0, 4, 8])  # 文件头部常见偏移
        for i in range(0, len(input_data), 16):  # 结构边界
            points.append(i)

        # 识别字符串结束符和分隔符
        for i, byte in enumerate(input_data):
            if byte in [0x00, 0x20, 0x2c, 0x3b]:  # NULL, space, comma, semicolon
                points.append(i)

        return list(set(points))

    def mutate(self, input_data: bytes) -> bytes:
        """执行基于语义的变异"""
        points = self.get_mutation_points(input_data)
        if not points:
            return input_data

        data = bytearray(input_data)
        num_mutations = random.randint(1, min(len(points), 4))

        for _ in range(num_mutations):
            pos = random.choice(points)
            if pos < len(data):
                mutation_type = random.choice(['flip', 'insert', 'delete', 'replace'])

                if mutation_type == 'flip':
                    data[pos] ^= random.randint(1, 255)
                elif mutation_type == 'insert' and len(data) < 2 * len(input_data):
                    data.insert(pos, random.randint(0, 255))
                elif mutation_type == 'delete' and len(data) > len(input_data) // 2:
                    del data[pos]
                elif mutation_type == 'replace':
                    # 替换为特殊值
                    special_values = [0x00, 0xff, 0x7f, 0x80, len(data)]
                    value = random.choice(special_values)
                    data[pos:pos + 1] = value.to_bytes(1, byteorder='big')

        return bytes(data)


class EnhancedFuzzFramework(FuzzFramework):
    def __init__(self, binary_path, input_dir, output_dir, timeout=24 * 3600):
        super().__init__(binary_path, input_dir, output_dir, timeout)
        self.semantic_mutator = SemanticMutator(binary_path)

    def run_enhanced_afl(self):
        env = os.environ.copy()
        env['AFL_CUSTOM_MUTATOR_LIBRARY'] = 'semantic_mutator.so'

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