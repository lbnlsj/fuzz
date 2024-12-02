import os
import sys
import time
import signal
import subprocess
import multiprocessing
from pathlib import Path
import json
import plotly.graph_objects as go


class FuzzFramework:
    def __init__(self, binary_path, input_dir, output_dir, timeout=24 * 3600):
        self.binary_path = binary_path
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.timeout = timeout

        # 创建必要的目录
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # AFL++相关配置
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

                # 收集覆盖率和崩溃数据
                self._collect_stats()
                time.sleep(60)  # 每分钟收集一次数据

            process.terminate()

        except Exception as e:
            print(f"Error running AFL++: {e}")

    def _collect_stats(self):
        # 读取AFL++的状态文件
        stats_file = self.output_dir / "default" / "fuzzer_stats"
        if not stats_file.exists():
            return

        with open(stats_file) as f:
            stats = {}
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    stats[key.strip()] = value.strip()

        # 收集关键指标
        self.coverage_data.append({
            "time": time.time(),
            "paths_total": int(stats.get("paths_total", 0)),
            "edge_coverage": int(stats.get("edges_found", 0))
        })

        self.crash_data.append({
            "time": time.time(),
            "unique_crashes": int(stats.get("unique_crashes", 0))
        })

    def generate_report(self):
        # 生成覆盖率图表
        fig = go.Figure()
        times = [(t["time"] - self.coverage_data[0]["time"]) / 3600 for t in self.coverage_data]

        fig.add_trace(go.Scatter(
            x=times,
            y=[d["edge_coverage"] for d in self.coverage_data],
            name="Edge Coverage"
        ))

        fig.add_trace(go.Scatter(
            x=times,
            y=[d["paths_total"] for d in self.coverage_data],
            name="Total Paths"
        ))

        fig.update_layout(
            title="Fuzzing Progress",
            xaxis_title="Time (hours)",
            yaxis_title="Count"
        )

        fig.write_html(self.output_dir / "coverage_report.html")

        # 保存原始数据
        with open(self.output_dir / "fuzz_data.json", "w") as f:
            json.dump({
                "coverage": self.coverage_data,
                "crashes": self.crash_data
            }, f, indent=2)


def main():
    # 测试数据集列表
    test_binaries = [
        "./benchmark/exiv2",
        "./benchmark/mp4box",
        "./benchmark/objdump",
    ]

    for binary in test_binaries:
        print(f"Testing {binary}")

        fuzzer = FuzzFramework(
            binary_path=binary,
            input_dir=f"./seeds/{Path(binary).name}",
            output_dir=f"./results/{Path(binary).name}"
        )

        fuzzer.run_afl()
        fuzzer.generate_report()


if __name__ == "__main__":
    main()