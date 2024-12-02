from typing import Dict, Set, List, Optional, Tuple
import networkx as nx
from collections import defaultdict
import logging


class TaintTag:
    """污点标签"""

    def __init__(self, source: str, offset: int, size: int):
        self.source = source  # 污点来源
        self.offset = offset  # 在输入中的偏移
        self.size = size  # 大小

    def __eq__(self, other):
        if not isinstance(other, TaintTag):
            return False
        return (self.source == other.source and
                self.offset == other.offset and
                self.size == other.size)

    def __hash__(self):
        return hash((self.source, self.offset, self.size))

    def __repr__(self):
        return f"TaintTag(source={self.source}, offset={self.offset}, size={self.size})"


class TaintedData:
    """被污染的数据"""

    def __init__(self, data: bytes, tags: Set[TaintTag]):
        self.data = data
        self.tags = tags

    def __repr__(self):
        return f"TaintedData(size={len(self.data)}, tags={len(self.tags)})"


class TaintTracker:
    """污点追踪器"""

    def __init__(self):
        self.taint_map: Dict[int, Set[TaintTag]] = {}  # 内存地址->污点标签映射
        self.taint_graph = nx.DiGraph()  # 污点传播图
        self.propagation_rules = defaultdict(list)  # 传播规则
        self.sanitizers = set()  # 清洗函数集合

    def add_taint_source(self, address: int, source: str,
                         offset: int, size: int):
        """添加污点源"""
        tag = TaintTag(source, offset, size)
        if address not in self.taint_map:
            self.taint_map[address] = set()
        self.taint_map[address].add(tag)
        self.taint_graph.add_node(address, tags={tag})

    def add_propagation_rule(self, opcode: str,
                             rule: callable):
        """添加传播规则"""
        self.propagation_rules[opcode].append(rule)

    def add_sanitizer(self, func_name: str):
        """添加清洗函数"""
        self.sanitizers.add(func_name)

    def get_taint_tags(self, address: int) -> Set[TaintTag]:
        """获取地址的污点标签"""
        return self.taint_map.get(address, set())

    def is_tainted(self, address: int) -> bool:
        """检查地址是否被污染"""
        return address in self.taint_map and len(self.taint_map[address]) > 0

    def propagate_taint(self, inst_addr: int, opcode: str,
                        operands: List[int], result: int):
        """传播污点"""
        if opcode in self.propagation_rules:
            for rule in self.propagation_rules[opcode]:
                new_tags = rule(self, operands)
                if new_tags:
                    if result not in self.taint_map:
                        self.taint_map[result] = set()
                    self.taint_map[result].update(new_tags)

                    # 更新传播图
                    self.taint_graph.add_node(result, tags=new_tags)
                    for operand in operands:
                        if self.is_tainted(operand):
                            self.taint_graph.add_edge(operand, result)

    def clear_taint(self, address: int):
        """清除污点"""
        if address in self.taint_map:
            del self.taint_map[address]
            self.taint_graph.remove_node(address)

    def handle_memory_store(self, source_addr: int,
                            dest_addr: int, size: int):
        """处理内存存储操作"""
        if self.is_tainted(source_addr):
            source_tags = self.get_taint_tags(source_addr)
            for offset in range(size):
                curr_addr = dest_addr + offset
                self.taint_map[curr_addr] = source_tags.copy()
                self.taint_graph.add_node(curr_addr, tags=source_tags)
                self.taint_graph.add_edge(source_addr, curr_addr)

    def handle_memory_load(self, source_addr: int,
                           dest_addr: int, size: int):
        """处理内存加载操作"""
        tags = set()
        for offset in range(size):
            curr_addr = source_addr + offset
            if self.is_tainted(curr_addr):
                tags.update(self.get_taint_tags(curr_addr))

        if tags:
            self.taint_map[dest_addr] = tags
            self.taint_graph.add_node(dest_addr, tags=tags)
            self.taint_graph.add_edge(source_addr, dest_addr)


class TaintAnalyzer:
    """污点分析器"""

    def __init__(self):
        self.tracker = TaintTracker()
        self.setup_default_rules()
        self.logger = logging.getLogger("TaintAnalyzer")

    def setup_default_rules(self):
        """设置默认的传播规则"""

        # 算术运算传播规则
        def arithmetic_rule(tracker, operands):
            tags = set()
            for operand in operands:
                if tracker.is_tainted(operand):
                    tags.update(tracker.get_taint_tags(operand))
            return tags

        # 位运算传播规则
        def bitwise_rule(tracker, operands):
            return arithmetic_rule(tracker, operands)

        # 数据移动传播规则
        def move_rule(tracker, operands):
            if len(operands) > 0 and tracker.is_tainted(operands[0]):
                return tracker.get_taint_tags(operands[0])
            return set()

        # 注册默认规则
        arithmetic_opcodes = {'add', 'sub', 'mul', 'div'}
        bitwise_opcodes = {'and', 'or', 'xor', 'shl', 'shr'}
        move_opcodes = {'mov', 'movzx', 'movsx'}

        for opcode in arithmetic_opcodes:
            self.tracker.add_propagation_rule(opcode, arithmetic_rule)
        for opcode in bitwise_opcodes:
            self.tracker.add_propagation_rule(opcode, bitwise_rule)
        for opcode in move_opcodes:
            self.tracker.add_propagation_rule(opcode, move_rule)

    def analyze_instruction(self, inst_addr: int, opcode: str,
                            operands: List[int], result: int):
        """分析指令"""
        try:
            self.tracker.propagate_taint(inst_addr, opcode, operands, result)
        except Exception as e:
            self.logger.error(f"Error analyzing instruction at {hex(inst_addr)}: {e}")

    def taint_memory(self, start_addr: int, data: bytes, source: str):
        """污染内存区域"""
        for i, _ in enumerate(data):
            self.tracker.add_taint_source(start_addr + i, source, i, 1)

    def track_taint_flow(self, start_addr: int,
                         end_addr: int) -> List[Tuple[int, Set[TaintTag]]]:
        """追踪污点流"""
        if not nx.has_path(self.tracker.taint_graph, start_addr, end_addr):
            return []

        path = nx.shortest_path(self.tracker.taint_graph, start_addr, end_addr)
        flow = []
        for addr in path:
            tags = self.tracker.get_taint_tags(addr)
            if tags:
                flow.append((addr, tags))
        return flow

    def get_tainted_inputs(self) -> Set[Tuple[int, int]]:
        """获取被污染的输入字节范围"""
        input_ranges = set()
        for tags in self.tracker.taint_map.values():
            for tag in tags:
                input_ranges.add((tag.offset, tag.offset + tag.size))
        return input_ranges

    def get_taint_influence(self, address: int) -> Set[int]:
        """获取污点影响的地址集合"""
        if address not in self.tracker.taint_graph:
            return set()

        return set(nx.descendants(self.tracker.taint_graph, address))

    def get_taint_sources(self, address: int) -> Set[TaintTag]:
        """获取污点来源"""
        if address not in self.tracker.taint_graph:
            return set()

        sources = set()
        for predecessor in nx.ancestors(self.tracker.taint_graph, address):
            sources.update(self.tracker.get_taint_tags(predecessor))
        return sources

    def visualize_taint_flow(self, output_file: str = "taint_flow.dot"):
        """可视化污点流"""
        try:
            # 为图添加标签
            for node in self.tracker.taint_graph.nodes():
                tags = self.tracker.get_taint_tags(node)
                label = f"{hex(node)}\n"
                label += "\n".join(str(tag) for tag in tags)
                self.tracker.taint_graph.nodes[node]['label'] = label

            # 保存图
            nx.drawing.nx_agraph.write_dot(self.tracker.taint_graph, output_file)
            print(f"Taint flow visualization saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to visualize taint flow: {e}")

    def generate_report(self) -> Dict:
        """生成分析报告"""
        return {
            'total_tainted_addresses': len(self.tracker.taint_map),
            'total_taint_tags': sum(len(tags)
                                    for tags in self.tracker.taint_map.values()),
            'tainted_input_ranges': list(self.get_tainted_inputs()),
            'taint_propagation_stats': {
                'nodes': self.tracker.taint_graph.number_of_nodes(),
                'edges': self.tracker.taint_graph.number_of_edges(),
                'connected_components':
                    nx.number_connected_components(
                        self.tracker.taint_graph.to_undirected()
                    )
            }
        }

