import argparse
import os
import time
import logging
from typing import List, Set, Optional
from pathlib import Path

from core.mutation import StructAwareMutator
from core.executor import Executor
from core.coverage import CoverageCollector
from analysis.structure import StructureAnalyzer
from utils.helper import (
    FileHelper,
    LogHelper,
    TimeHelper,
    StatsHelper,
    PathHelper
)


class StructAwareFuzzer:
    """基准版本结构感知模糊测试器"""

    def __init__(self, target_path: str, corpus_dir: str, output_dir: str,
                 timeout: int = 1):
        self.target_path = target_path
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.timeout = timeout

        # 创建必要目录
        self.crashes_dir = os.path.join(output_dir, "crashes")
        self.queue_dir = os.path.join(output_dir, "queue")
        self.stats_dir = os.path.join(output_dir, "stats")
        for d in [self.crashes_dir, self.queue_dir, self.stats_dir]:
            PathHelper.ensure_dir(d)

        # 初始化组件
        self.mutator = StructAwareMutator()
        self.executor = Executor(target_path, timeout)
        self.analyzer = StructureAnalyzer()
        self.coverage = CoverageCollector(target_path)

        # 初始化状态
        self.corpus: List[bytes] = []
        self.unique_crashes: Set[str] = set()
        self.total_executions = 0
        self.last_new_path = 0
        self.start_time = time.time()

        # 设置日志
        self.logger = LogHelper.setup_logger(
            "fuzzer",
            os.path.join(output_dir, "fuzzer.log")
        )

        # 初始化统计信息
        self.stats = {
            'total_executions': 0,
            'unique_crashes': 0,
            'corpus_size': 0,
            'coverage': {
                'edges': 0,
                'blocks': 0
            },
            'execution_time': [],
            'last_new_path_time': 0,
            'last_crash_time': 0
        }

    def load_corpus(self):
        """加载初始语料库"""
        self.logger.info("Loading initial corpus...")
        loaded_count = 0

        for file_path in Path(self.corpus_dir).glob("*"):
            try:
                data = FileHelper.read_binary(str(file_path))
                if data:
                    self.corpus.append(data)
                    loaded_count += 1
                    self.logger.debug(f"Loaded corpus file: {file_path}")
            except Exception as e:
                self.logger.error(f"Error loading {file_path}: {e}")

        self.logger.info(f"Loaded {loaded_count} corpus files")

    def save_crash(self, data: bytes, crash_info: str):
        """保存崩溃样本"""
        crash_hash = FileHelper.get_file_hash(data)
        if crash_hash not in self.unique_crashes:
            self.unique_crashes.add(crash_hash)

            # 保存崩溃样本
            crash_path = os.path.join(
                self.crashes_dir,
                f"crash_{crash_hash}.bin"
            )
            if FileHelper.write_binary(crash_path, data):
                # 保存崩溃信息
                info_path = crash_path + ".info"
                with open(info_path, "w") as f:
                    f.write(crash_info)
                    f.write("\n\nStack Trace:\n")
                    f.write(self.executor.get_stack_trace())

                self.logger.info(f"New crash saved: {crash_path}")
                self.stats['last_crash_time'] = time.time()

    def save_interesting_input(self, data: bytes):
        """保存有趣的输入"""
        input_hash = FileHelper.get_file_hash(data)
        path = os.path.join(
            self.queue_dir,
            f"id_{len(self.corpus)}_{input_hash}.bin"
        )
        FileHelper.write_binary(path, data)

    def select_next_input(self) -> Optional[bytes]:
        """选择下一个待测试输入"""
        if not self.corpus:
            return None

        # 基于覆盖率和新颖性选择
        best_score = -1
        best_input = None

        for input_data in self.corpus[-10:]:  # 关注最近添加的输入
            score = self._calculate_input_score(input_data)
            if score > best_score:
                best_score = score
                best_input = input_data

        return best_input or self.corpus[-1]

    def _calculate_input_score(self, data: bytes) -> float:
        """计算输入的分数"""
        score = 0.0

        # 分析结构复杂度
        try:
            structure = self.analyzer.analyze_structure(data)
            score += len(structure.get_all_fields()) * 0.1
            score += len(structure.children) * 0.2
        except:
            pass

        # 考虑覆盖率贡献
        coverage_map = self.coverage.get_coverage(FileHelper.get_file_hash(data))
        if coverage_map:
            score += len(coverage_map.edges) * 0.5
            score += len(coverage_map.blocks) * 0.3

        return score

    def run(self, max_iterations: int = None):
        """运行模糊测试"""
        self.logger.info("Starting fuzzing...")
        self.load_corpus()

        iteration = 0
        try:
            while True:
                if max_iterations and iteration >= max_iterations:
                    break

                # 选择输入
                seed = self.select_next_input()
                if not seed:
                    self.logger.error("No valid input available!")
                    break

                # 分析输入结构
                structure = self.analyzer.analyze_structure(seed)

                # 变异输入
                start_time = time.time()
                mutated_data = self.mutator.mutate(
                    seed,
                    structure.get_all_fields(),
                    structure.children
                )

                # 执行变异后的输入
                return_code, error_msg = self.executor.run_target(mutated_data)
                exec_time = time.time() - start_time

                self.total_executions += 1
                self.stats['total_executions'] = self.total_executions
                self.stats['execution_time'].append(exec_time)

                # 收集覆盖率
                coverage_info = self.coverage.get_coverage(mutated_data)

                # 处理执行结果
                if self.executor.is_crash(return_code):
                    crash_info = self.executor.get_crash_info(error_msg)
                    self.save_crash(mutated_data, crash_info)
                    self.stats['unique_crashes'] = len(self.unique_crashes)

                elif self.coverage.is_new_coverage(coverage_info):
                    # 发现新路径
                    self.corpus.append(mutated_data)
                    self.save_interesting_input(mutated_data)
                    self.last_new_path = time.time()
                    self.stats['last_new_path_time'] = self.last_new_path
                    self.logger.info(
                        f"New coverage found! Corpus size: {len(self.corpus)}"
                    )

                # 更新统计信息
                if iteration % 100 == 0:
                    self._update_stats()
                    self._print_status()

                # 检查是否停滞
                if self._check_stalling():
                    self.logger.warning("Fuzzing appears to be stalled...")
                    # 可以在这里添加策略调整

                iteration += 1

        except KeyboardInterrupt:
            self.logger.info("\nFuzzing interrupted by user.")
        finally:
            self._print_final_stats()
            self._save_stats()

    def _update_stats(self):
        """更新统计信息"""
        coverage_stats = self.coverage.get_coverage_stats()
        self.stats.update({
            'corpus_size': len(self.corpus),
            'coverage': coverage_stats,
            'run_time': TimeHelper.get_elapsed_time(self.start_time)
        })

    def _save_stats(self):
        """保存统计信息"""
        stats_file = os.path.join(self.stats_dir, "fuzzing_stats.json")
        StatsHelper.save_stats(self.stats, stats_file)

    def _print_status(self):
        """打印状态信息"""
        elapsed = time.time() - self.start_time
        exec_per_sec = self.total_executions / elapsed if elapsed > 0 else 0

        status = (
            f"\n{'=' * 50}\n"
            f"Runtime: {TimeHelper.get_elapsed_time(self.start_time)}\n"
            f"Total executions: {self.total_executions}\n"
            f"Executions/sec: {exec_per_sec:.2f}\n"
            f"Corpus size: {len(self.corpus)}\n"
            f"Unique crashes: {len(self.unique_crashes)}\n"
            f"Coverage: {self.stats['coverage']}\n"
            f"{'=' * 50}\n"
        )

        self.logger.info(status)

    def _print_final_stats(self):
        """打印最终统计信息"""
        self.logger.info("\nFinal Statistics:")
        self.logger.info(f"Total executions: {self.total_executions}")
        self.logger.info(f"Total unique crashes: {len(self.unique_crashes)}")
        self.logger.info(f"Final corpus size: {len(self.corpus)}")
        self.logger.info(f"Total runtime: {TimeHelper.get_elapsed_time(self.start_time)}")

    def _check_stalling(self) -> bool:
        """检查是否停滞"""
        if not self.last_new_path:
            return False

        stall_time = time.time() - self.last_new_path
        # 如果15分钟没有新路径,认为停滞
        return stall_time > 900


def main():
    parser = argparse.ArgumentParser(description="Structure-aware Fuzzer")
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
        "--timeout",
        help="Execution timeout in seconds",
        type=int,
        default=1
    )
    parser.add_argument(
        "--max-iterations",
        help="Maximum number of iterations",
        type=int,
        default=None
    )

    args = parser.parse_args()

    fuzzer = StructAwareFuzzer(
        args.target,
        args.corpus,
        args.output,
        args.timeout
    )

    try:
        fuzzer.run(args.max_iterations)
    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        print("\nFuzzing session finished.")


if __name__ == "__main__":
    main()