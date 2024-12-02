import argparse
import os
import time
from typing import List, Set, Type
from pathlib import Path

from core.mutation import StructAwareMutator
from core.adaptive_mutation import AdaptiveStructAwareMutator
from core.executor import Executor
from core.coverage import CoverageCollector
from analysis.structure import StructureAnalyzer
from analysis.dl_structure import DLStructureAwareMutator, DeepStructureAnalyzer


class EnhancedStructAwareFuzzer:
    """增强版结构感知模糊测试器"""

    def __init__(self, target_path: str, corpus_dir: str, output_dir: str,
                 mode: str = 'baseline', timeout: int = 1,
                 model_path: str = None):
        self.target_path = target_path
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.mode = mode

        # 根据模式选择变异器
        if mode == 'baseline':
            self.mutator = StructAwareMutator()
            self.analyzer = StructureAnalyzer()
        elif mode == 'adaptive':
            self.mutator = AdaptiveStructAwareMutator()
            self.analyzer = StructureAnalyzer()
        elif mode == 'deep_learning':
            self.mutator = DLStructureAwareMutator(model_path)
            self.analyzer = DeepStructureAnalyzer(model_path)
        else:
            raise ValueError(f"Unknown mode: {mode}")

        # 初始化其他组件
        self.executor = Executor(target_path, timeout)
        self.coverage = CoverageCollector(target_path)

        # 初始化状态
        self.corpus: List[bytes] = []
        self.unique_crashes: Set[str] = set()
        self.total_executions = 0
        self.start_time = time.time()
        self.stats = {
            'iterations': 0,
            'new_coverage': 0,
            'crashes': 0,
            'exec_time': [],
            'coverage_progress': []
        }

        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "crashes"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "corpus"), exist_ok=True)

    def load_corpus(self):
        """加载初始语料库"""
        for file_path in Path(self.corpus_dir).glob("*"):
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                self.corpus.append(data)
                print(f"Loaded corpus file: {file_path}")
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

    def save_crash(self, data: bytes, crash_info: str):
        """保存崩溃样本"""
        crash_hash = hash(data + crash_info.encode())
        if crash_hash not in self.unique_crashes:
            self.unique_crashes.add(crash_hash)
            crash_path = os.path.join(
                self.output_dir,
                "crashes",
                f"crash_{crash_hash}.bin"
            )
            with open(crash_path, "wb") as f:
                f.write(data)
            with open(crash_path + ".info", "w") as f:
                f.write(crash_info)
            print(f"New crash saved: {crash_path}")
            self.stats['crashes'] += 1

    def save_interesting_input(self, data: bytes, reason: str):
        """保存有趣的输入"""
        input_hash = hash(data)
        path = os.path.join(
            self.output_dir,
            "corpus",
            f"interesting_{input_hash}.bin"
        )
        with open(path, "wb") as f:
            f.write(data)

    def update_stats(self, iteration: int, exec_time: float,
                     new_coverage: bool):
        """更新统计信息"""
        self.stats['iterations'] = iteration
        self.stats['exec_time'].append(exec_time)
        if new_coverage:
            self.stats['new_coverage'] += 1
        self.stats['coverage_progress'].append(
            self.coverage.get_total_coverage()
        )

    def save_stats(self):
        """保存统计信息"""
        stats_path = os.path.join(self.output_dir, "stats.json")
        with open(stats_path, "w") as f:
            json.dump(self.stats, f, indent=2)

    def run(self, max_iterations: int = None):
        """运行模糊测试"""
        print(f"Starting fuzzing in {self.mode} mode...")
        self.load_corpus()

        iteration = 0
        try:
            while True:
                if max_iterations and iteration >= max_iterations:
                    break

                # 选择输入进行变异
                if not self.corpus:
                    print("Error: Empty corpus!")
                    break

                seed = self.corpus[iteration % len(self.corpus)]

                # 分析输入结构
                start_time = time.time()
                structure = self.analyzer.analyze_structure(seed)

                # 变异输入
                mutated_data = self.mutator.mutate(
                    seed,
                    structure.fields,
                    structure.children
                )

                # 执行变异后的输入
                return_code, error_msg = self.executor.run_target(mutated_data)
                exec_time = time.time() - start_time
                self.total_executions += 1

                # 收集覆盖率
                coverage_info = self.coverage.get_coverage(mutated_data)
                new_coverage = self.coverage.is_new_coverage(coverage_info)

                # 更新自适应变异器的历史记录（如果使用）
                if self.mode == 'adaptive':
                    self.mutator.update_history(
                        strategy=self.mutator.last_strategy,
                        success=new_coverage
                    )

                # 处理执行结果
                if self.executor.is_crash(return_code):
                    crash_info = self.executor.get_crash_info(error_msg)
                    self.save_crash(mutated_data, crash_info)
                elif new_coverage:
                    self.corpus.append(mutated_data)
                    self.save_interesting_input(
                        mutated_data,
                        "new_coverage"
                    )
                    print(f"New coverage found! Corpus size: {len(self.corpus)}")

                # 更新统计信息
                self.update_stats(iteration, exec_time, new_coverage)

                # 定期打印状态
                if iteration % 100 == 0:
                    self._print_status(iteration)
                    self.save_stats()

                iteration += 1

        except KeyboardInterrupt:
            print("\nFuzzing interrupted by user.")
        finally:
            self._print_final_stats()
            self.save_stats()

    def _print_status(self, iteration: int):
        """打印状态信息"""
        elapsed = time.time() - self.start_time
        execs_per_sec = self.total_executions / elapsed

        print("\n" + "=" * 50)
        print(f"Mode: {self.mode}")
        print(f"Iteration: {iteration}")
        print(f"Total executions: {self.total_executions}")
        print(f"Executions/sec: {execs_per_sec:.2f}")
        print(f"Corpus size: {len(self.corpus)}")
        print(f"Unique crashes: {len(self.unique_crashes)}")
        print(f"Total coverage: {self.coverage.get_total_coverage()}")

        if self.mode == 'adaptive':
            print("\nStrategy weights:")
            for level, weights in self.mutator.get_strategy_weights().items():
                print(f"{level}:")
                for strategy, weight in weights.items():
                    print(f"  {strategy}: {weight:.3f}")

        print("=" * 50 + "\n")

    def _print_final_stats(self):
        """打印最终统计信息"""
        print("\nFinal Statistics:")
        print(f"Total iterations: {self.stats['iterations']}")
        print(f"Total crashes found: {self.stats['crashes']}")
        print(f"New coverage events: {self.stats['new_coverage']}")
        print(f"Average execution time: {np.mean(self.stats['exec_time']):.3f}s")
        print(f"Final coverage: {self.coverage.get_total_coverage()}")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Structure-aware Fuzzer"
    )
    parser.add_argument("target", help="Path to target program")
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
        "--mode",
        help="Fuzzing mode (baseline, adaptive, or deep_learning)",
        choices=['baseline', 'adaptive', 'deep_learning'],
        default='baseline'
    )
    parser.add_argument(
        "--timeout",
        help="Execution timeout (seconds)",
        type=int,
        default=1
    )
    parser.add_argument(
        "--max-iterations",
        help="Maximum number of iterations",
        type=int,
        default=None
    )
    parser.add_argument(
        "--model-path",
        help="Path to pre-trained deep learning model",
        default=None
    )

    args = parser.parse_args()

    fuzzer = EnhancedStructAwareFuzzer(
        args.target,
        args.corpus,
        args.output,
        args.mode,
        args.timeout,
        args.model_path
    )

    try:
        fuzzer.run(args.max_iterations)
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user.")
    finally:
        print("\nFuzzing session finished.")


if __name__ == "__main__":
    main()