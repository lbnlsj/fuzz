from typing import Dict, Set, List, Tuple
import subprocess
import os
import json
from collections import defaultdict
import hashlib
import logging
from pathlib import Path
import time


class Edge:
    """边信息类"""

    def __init__(self, source: int, target: int, hit_count: int = 0):
        self.source = source
        self.target = target
        self.hit_count = hit_count

    def __eq__(self, other):
        if not isinstance(other, Edge):
            return False
        return (self.source == other.source and
                self.target == other.target)

    def __hash__(self):
        return hash((self.source, self.target))

    def __repr__(self):
        return f"Edge({self.source}->{self.target}, hits={self.hit_count})"


class BasicBlock:
    """基本块信息类"""

    def __init__(self, address: int, size: int = 0):
        self.address = address
        self.size = size
        self.instructions: Set[int] = set()
        self.incoming: Set[int] = set()
        self.outgoing: Set[int] = set()
        self.hit_count = 0

    def add_instruction(self, address: int):
        """添加指令地址"""
        self.instructions.add(address)
        self.size = max(self.size, len(self.instructions))

    def __repr__(self):
        return f"BasicBlock(addr={hex(self.address)}, size={self.size})"


class CoverageMap:
    """覆盖率映射"""

    def __init__(self):
        self.edges: Set[Edge] = set()
        self.blocks: Dict[int, BasicBlock] = {}
        self.total_edges = 0
        self.total_blocks = 0

    def add_edge(self, source: int, target: int):
        """添加边"""
        edge = Edge(source, target)
        self.edges.add(edge)

        # 更新基本块信息
        if source not in self.blocks:
            self.blocks[source] = BasicBlock(source)
        if target not in self.blocks:
            self.blocks[target] = BasicBlock(target)

        self.blocks[source].outgoing.add(target)
        self.blocks[target].incoming.add(source)

    def get_coverage_stats(self) -> Dict:
        """获取覆盖率统计信息"""
        covered_edges = len(self.edges)
        covered_blocks = len([b for b in self.blocks.values() if b.hit_count > 0])

        return {
            'edge_coverage': {
                'covered': covered_edges,
                'total': self.total_edges,
                'percentage': (covered_edges / self.total_edges * 100
                               if self.total_edges else 0)
            },
            'block_coverage': {
                'covered': covered_blocks,
                'total': self.total_blocks,
                'percentage': (covered_blocks / self.total_blocks * 100
                               if self.total_blocks else 0)
            }
        }


class CoverageCollector:
    """覆盖率收集器"""

    def __init__(self, target_binary: str):
        self.target_binary = target_binary
        self.coverage_maps: Dict[str, CoverageMap] = {}
        self.global_coverage = CoverageMap()
        self.logger = logging.getLogger("CoverageCollector")

        # 初始化工作目录
        self.work_dir = "_coverage_work"
        os.makedirs(self.work_dir, exist_ok=True)

    def instrument_binary(self) -> str:
        """插桩目标二进制"""
        instrumented_path = os.path.join(
            self.work_dir,
            f"{Path(self.target_binary).stem}_inst"
        )

        try:
            # 使用 afl-gcc 进行插桩
            cmd = [
                "afl-gcc",
                "-o", instrumented_path,
                self.target_binary
            ]
            subprocess.run(cmd, check=True)
            return instrumented_path
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Instrumentation failed: {e}")
            return self.target_binary

    def collect_coverage(self, input_data: bytes) -> Tuple[CoverageMap, bool]:
        """收集单个输入的覆盖率"""
        # 计算输入的哈希值作为标识
        input_hash = hashlib.md5(input_data).hexdigest()

        # 如果已经收集过这个输入的覆盖率,直接返回
        if input_hash in self.coverage_maps:
            return self.coverage_maps[input_hash], False

        # 将输入写入临时文件
        input_file = os.path.join(self.work_dir, f"input_{input_hash}")
        with open(input_file, "wb") as f:
            f.write(input_data)

        coverage_map = CoverageMap()
        try:
            # 运行插桩后的程序
            instrumented_binary = self.instrument_binary()
            env = os.environ.copy()
            env['AFL_MAP_SIZE'] = '65536'

            proc = subprocess.run(
                [instrumented_binary, input_file],
                env=env,
                capture_output=True,
                timeout=10
            )

            # 解析覆盖率信息
            if proc.returncode == 0:
                coverage_file = os.path.join(self.work_dir, ".cur_coverage")
                if os.path.exists(coverage_file):
                    with open(coverage_file, "rb") as f:
                        coverage_data = f.read()
                        self._parse_coverage_data(coverage_data, coverage_map)

            # 更新全局覆盖率
            new_coverage = self._update_global_coverage(coverage_map)

            # 保存覆盖率映射
            self.coverage_maps[input_hash] = coverage_map

            return coverage_map, new_coverage

        except Exception as e:
            self.logger.error(f"Coverage collection failed: {e}")
            return coverage_map, False

        finally:
            # 清理临时文件
            if os.path.exists(input_file):
                os.remove(input_file)

    def _parse_coverage_data(self, data: bytes, coverage_map: CoverageMap):
        """解析覆盖率数据"""
        if len(data) < 8:
            return

        # 解析边信息
        for i in range(0, len(data) - 8, 8):
            source = int.from_bytes(data[i:i + 4], byteorder='little')
            target = int.from_bytes(data[i + 4:i + 8], byteorder='little')
            if source and target:
                coverage_map.add_edge(source, target)

    def _update_global_coverage(self, coverage_map: CoverageMap) -> bool:
        """更新全局覆盖率"""
        new_coverage = False

        # 检查新的边
        for edge in coverage_map.edges:
            if edge not in self.global_coverage.edges:
                self.global_coverage.add_edge(edge.source, edge.target)
                new_coverage = True

        return new_coverage

    def generate_coverage_report(self, output_dir: str):
        """生成覆盖率报告"""
        os.makedirs(output_dir, exist_ok=True)

        # 生成概要报告
        summary = {
            'global_coverage': self.global_coverage.get_coverage_stats(),
            'total_inputs': len(self.coverage_maps),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        with open(os.path.join(output_dir, "coverage_summary.json"), "w") as f:
            json.dump(summary, f, indent=2)

        # 生成详细报告
        detailed_report = {
            'edges': [
                {
                    'source': hex(edge.source),
                    'target': hex(edge.target),
                    'hit_count': edge.hit_count
                }
                for edge in self.global_coverage.edges
            ],
            'blocks': [
                {
                    'address': hex(block.address),
                    'size': block.size,
                    'hit_count': block.hit_count,
                    'incoming': len(block.incoming),
                    'outgoing': len(block.outgoing)
                }
                for block in self.global_coverage.blocks.values()
            ]
        }

        with open(os.path.join(output_dir, "coverage_detailed.json"), "w") as f:
            json.dump(detailed_report, f, indent=2)

        # 生成可视化报告
        self._generate_visualization(output_dir)

    def _generate_visualization(self, output_dir: str):
        """生成覆盖率可视化"""
        try:
            import graphviz

            # 创建控制流图
            dot = graphviz.Digraph(comment='Coverage Visualization')
            dot.attr(rankdir='LR')

            # 添加基本块节点
            for block in self.global_coverage.blocks.values():
                color = 'lightblue' if block.hit_count > 0 else 'white'
                dot.node(
                    hex(block.address),
                    f"Block {hex(block.address)}\nHits: {block.hit_count}",
                    style='filled',
                    fillcolor=color
                )

            # 添加边
            for edge in self.global_coverage.edges:
                dot.edge(
                    hex(edge.source),
                    hex(edge.target),
                    label=str(edge.hit_count)
                )

            # 保存图
            dot.render(
                os.path.join(output_dir, "coverage_graph"),
                format='png',
                cleanup=True
            )

        except ImportError:
            self.logger.warning("graphviz not installed, skipping visualization")

    def cleanup(self):
        """清理工作目录"""
        import shutil
        if os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)

