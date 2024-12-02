import os
import json
import time
import argparse
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from fuzzer.enhanced_main import EnhancedStructAwareFuzzer


class FuzzingEvaluator:
    """模糊测试评估器"""

    def __init__(self, target_programs: List[str], corpus_dir: str,
                 output_dir: str, iterations: int = 10000,
                 timeout: int = 1, runs: int = 5):
        self.target_programs = target_programs
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.iterations = iterations
        self.timeout = timeout
        self.runs = runs
        self.modes = ['baseline', 'adaptive', 'deep_learning']

    def run_single_evaluation(self, args) -> Dict:
        """运行单次评估"""
        target, mode, run_id = args

        output_subdir = os.path.join(
            self.output_dir,
            f"{Path(target).stem}_{mode}_run{run_id}"
        )

        fuzzer = EnhancedStructAwareFuzzer(
            target,
            self.corpus_dir,
            output_subdir,
            mode,
            self.timeout
        )

        # 运行fuzzing
        fuzzer.run(self.iterations)

        # 收集结果
        return {
            'target': target,
            'mode': mode,
            'run_id': run_id,
            'stats': fuzzer.stats,
            'final_coverage': fuzzer.coverage.get_total_coverage(),
            'crashes': len(fuzzer.unique_crashes),
            'corpus_size': len(fuzzer.corpus)
        }

    def run_evaluations(self):
        """运行所有评估"""
        evaluation_args = []
        for target in self.target_programs:
            for mode in self.modes:
                for run in range(self.runs):
                    evaluation_args.append((target, mode, run))

        # 并行执行评估
        with ProcessPoolExecutor() as executor:
            results = list(executor.map(self.run_single_evaluation,
                                        evaluation_args))

        self.analyze_results(results)

    def analyze_results(self, results: List[Dict]):
        """分析评估结果"""
        # 按目标程序分组结果
        grouped_results = {}
        for result in results:
            target = result['target']
            if target not in grouped_results:
                grouped_results[target] = []
            grouped_results[target].append(result)

        # 分析每个目标程序
        for target, target_results in grouped_results.items():
            self.analyze_target_results(target, target_results)

    def analyze_target_results(self, target: str, results: List[Dict]):
        """分析单个目标程序的结果"""
        # 按模式分组
        mode_results = {mode: [] for mode in self.modes}
        for result in results:
            mode_results[result['mode']].append(result)

        # 计算统计数据
        stats = {mode: {
            'coverage': {
                'mean': np.mean([r['final_coverage']['total_edges']
                                 for r in results]),
                'std': np.std([r['final_coverage']['total_edges']
                               for r in results])
            },
            'crashes': {
                'mean': np.mean([r['crashes'] for r in results]),
                'std': np.std([r['crashes'] for r in results])
            },
            'corpus_size': {
                'mean': np.mean([r['corpus_size'] for r in results]),
                'std': np.std([r['corpus_size'] for r in results])
            },
            'time_to_first_crash': {
                'mean': np.mean([min([
                                         i for i, c in enumerate(r['stats']['coverage_progress'])
                                         if c['crashes'] > 0
                                     ] or [self.iterations]) for r in results]),
                'std': np.std([min([
                                       i for i, c in enumerate(r['stats']['coverage_progress'])
                                       if c['crashes'] > 0
                                   ] or [self.iterations]) for r in results])
            }
        } for mode, results in mode_results.items()}

        # 生成报告
        self.generate_report(target, stats)

        # 生成图表
        self.generate_plots(target, mode_results)

    def generate_report(self, target: str, stats: Dict):
        """生成评估报告"""
        report_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, f"{Path(target).stem}_report.txt")

        with open(report_path, "w") as f:
            f.write(f"Evaluation Report for {target}\n")
            f.write("=" * 50 + "\n\n")

            for mode in self.modes:
                f.write(f"\n{mode.upper()} Mode Results:\n")
                f.write("-" * 30 + "\n")

                mode_stats = stats[mode]

                f.write(f"Coverage (edges):\n")
                f.write(f"  Mean: {mode_stats['coverage']['mean']:.2f}\n")
                f.write(f"  Std:  {mode_stats['coverage']['std']:.2f}\n\n")

                f.write(f"Crashes:\n")
                f.write(f"  Mean: {mode_stats['crashes']['mean']:.2f}\n")
                f.write(f"  Std:  {mode_stats['crashes']['std']:.2f}\n\n")

                f.write(f"Corpus Size:\n")
                f.write(f"  Mean: {mode_stats['corpus_size']['mean']:.2f}\n")
                f.write(f"  Std:  {mode_stats['corpus_size']['std']:.2f}\n\n")

                f.write(f"Time to First Crash (iterations):\n")
                f.write(
                    f"  Mean: {mode_stats['time_to_first_crash']['mean']:.2f}\n"
                )
                f.write(
                    f"  Std:  {mode_stats['time_to_first_crash']['std']:.2f}\n"
                )
                f.write("\n")

    def generate_plots(self, target: str, mode_results: Dict):
        """生成评估图表"""
        plot_dir = os.path.join(self.output_dir, "plots")
        os.makedirs(plot_dir, exist_ok=True)

        # 覆盖率增长曲线
        plt.figure(figsize=(10, 6))
        for mode, results in mode_results.items():
            coverage_progress = []
            for result in results:
                progress = [c['total_edges']
                            for c in result['stats']['coverage_progress']]
                coverage_progress.append(progress)

            mean_progress = np.mean(coverage_progress, axis=0)
            std_progress = np.std(coverage_progress, axis=0)

            x = range(len(mean_progress))
            plt.plot(x, mean_progress, label=mode)
            plt.fill_between(x,
                             mean_progress - std_progress,
                             mean_progress + std_progress,
                             alpha=0.2)

        plt.xlabel('Iterations')
        plt.ylabel('Edge Coverage')
        plt.title(f'Coverage Growth - {Path(target).stem}')
        plt.legend()
        plt.grid(True)

        plt.savefig(os.path.join(
            plot_dir,
            f"{Path(target).stem}_coverage.png"
        ))
        plt.close()

        # 性能对比柱状图
        metrics = ['coverage', 'crashes', 'corpus_size', 'time_to_first_crash']
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        axes = axes.flatten()

        for i, metric in enumerate(metrics):
            means = []
            stds = []
            for mode in self.modes:
                results = mode_results[mode]
                if metric == 'coverage':
                    values = [r['final_coverage']['total_edges']
                              for r in results]
                elif metric == 'time_to_first_crash':
                    values = [min([
                                      i for i, c in enumerate(r['stats']['coverage_progress'])
                                      if c['crashes'] > 0
                                  ] or [self.iterations]) for r in results]
                else:
                    values = [r[metric] for r in results]

                means.append(np.mean(values))
                stds.append(np.std(values))

            ax = axes[i]
            x = range(len(self.modes))
            ax.bar(x, means, yerr=stds, capsize=5,
                   tick_label=self.modes)
            ax.set_title(f'{metric.replace("_", " ").title()}')
            ax.grid(True)

        plt.tight_layout()
        plt.savefig(os.path.join(
            plot_dir,
            f"{Path(target).stem}_comparison.png"
        ))
        plt.close()


def main():
    parser = argparse.ArgumentParser(description="Fuzzing Evaluation Tool")
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Paths to target programs",
        required=True
    )
    parser.add_argument(
        "--corpus",
        help="Path to corpus directory",
        required=True
    )
    parser.add_argument(
        "--output",
        help="Path to output directory",
        required=True
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="Number of iterations per run"
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="Number of runs per configuration"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1,
        help="Execution timeout in seconds"
    )

    args = parser.parse_args()

    evaluator = FuzzingEvaluator(
        args.targets,
        args.corpus,
        args.output,
        args.iterations,
        args.timeout,
        args.runs
    )

    evaluator.run_evaluations()


if __name__ == "__main__":
    main()