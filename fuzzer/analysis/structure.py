from typing import Dict, List, Optional, Tuple, Set
import networkx as nx
from collections import defaultdict
import struct


class Field:
    """字段信息类"""

    def __init__(self, start: int, end: int, field_type: str,
                 value: bytes = None, dependencies: List[str] = None):
        self.start = start
        self.end = end
        self.field_type = field_type
        self.value = value
        self.dependencies = dependencies or []
        self.size = end - start

    def __repr__(self):
        return f"Field(type={self.field_type}, start={self.start}, end={self.end})"


class Structure:
    """结构信息类"""

    def __init__(self, start: int, end: int, struct_type: str):
        self.start = start
        self.end = end
        self.struct_type = struct_type
        self.fields: List[Field] = []
        self.children: List['Structure'] = []
        self.parent: Optional['Structure'] = None
        self.size = end - start

    def add_field(self, field: Field):
        """添加字段"""
        self.fields.append(field)

    def add_child(self, child: 'Structure'):
        """添加子结构"""
        self.children.append(child)
        child.parent = self

    def get_field_by_type(self, field_type: str) -> Optional[Field]:
        """根据类型获取字段"""
        for field in self.fields:
            if field.field_type == field_type:
                return field
        return None

    def get_all_fields(self) -> List[Field]:
        """获取所有字段(包括子结构)"""
        fields = self.fields.copy()
        for child in self.children:
            fields.extend(child.get_all_fields())
        return fields

    def __repr__(self):
        return (f"Structure(type={self.struct_type}, start={self.start}, "
                f"end={self.end}, fields={len(self.fields)}, "
                f"children={len(self.children)})")


class StructureAnalyzer:
    """结构分析器"""

    def __init__(self):
        self.known_signatures = {
            b'PNG\r\n\x1a\n': 'png',
            b'GIF8': 'gif',
            b'\xff\xd8\xff': 'jpeg',
            b'PK\x03\x04': 'zip',
            b'%PDF': 'pdf',
            b'\x89MPQ': 'mpq'
        }

        self.type_patterns = {
            'length': [
                (4, '<I'),  # 小端 4字节整数
                (4, '>I'),  # 大端 4字节整数
                (2, '<H'),  # 小端 2字节整数
                (2, '>H'),  # 大端 2字节整数
            ],
            'offset': [
                (4, '<I'),
                (4, '>I'),
                (8, '<Q'),
                (8, '>Q'),
            ]
        }

    def analyze_structure(self, data: bytes) -> Structure:
        """分析输入数据结构"""
        file_type = self._identify_file_type(data)
        root = Structure(0, len(data), file_type)

        # 分析主结构
        self._analyze_main_structure(data, root)

        # 识别字段类型和依赖关系
        self._identify_field_types(root)
        self._analyze_dependencies(root)

        return root

    def _identify_file_type(self, data: bytes) -> str:
        """识别文件类型"""
        for sig, ftype in self.known_signatures.items():
            if data.startswith(sig):
                return ftype
        return 'unknown'

    def _analyze_main_structure(self, data: bytes, structure: Structure):
        """分析主要结构"""
        pos = 0
        while pos < len(data):
            # 尝试识别块结构
            block_info = self._identify_block(data[pos:])
            if block_info:
                block_size, block_type = block_info
                if block_size > 0 and pos + block_size <= len(data):
                    block = Structure(pos, pos + block_size, block_type)
                    self._analyze_block_fields(data[pos:pos + block_size], block)
                    structure.add_child(block)
                    pos += block_size
                    continue

            # 如果没有识别出块结构,尝试识别单个字段
            field_info = self._identify_field(data[pos:])
            if field_info:
                field_size, field_type = field_info
                field = Field(pos, pos + field_size, field_type,
                              data[pos:pos + field_size])
                structure.add_field(field)
                pos += field_size
            else:
                pos += 1

    def _identify_block(self, data: bytes) -> Optional[Tuple[int, str]]:
        """识别数据块"""
        if len(data) < 8:
            return None

        # 尝试解析块大小
        for size_format in [(4, '<I'), (4, '>I'), (8, '<Q'), (8, '>Q')]:
            try:
                size = struct.unpack(size_format[1],
                                     data[:size_format[0]])[0]
                if 8 <= size <= len(data):
                    # 尝试识别块类型
                    type_data = data[size_format[0]:size_format[0] + 4]
                    block_type = type_data.decode('ascii', errors='ignore')
                    if block_type.isalnum():
                        return size, block_type
            except:
                continue

        return None

    def _identify_field(self, data: bytes) -> Optional[Tuple[int, str]]:
        """识别字段"""
        if len(data) < 2:
            return None

        # 尝试识别各种类型的字段
        for field_type, patterns in self.type_patterns.items():
            for size, fmt in patterns:
                if len(data) >= size:
                    try:
                        value = struct.unpack(fmt, data[:size])[0]
                        # 验证值的合理性
                        if self._is_valid_value(value, field_type):
                            return size, field_type
                    except:
                        continue

        return None

    def _is_valid_value(self, value: int, field_type: str) -> bool:
        """验证字段值是否合理"""
        if field_type == 'length':
            return 0 <= value <= 1024 * 1024 * 10  # 最大10MB
        elif field_type == 'offset':
            return 0 <= value <= 1024 * 1024 * 100  # 最大100MB
        return True

    def _analyze_block_fields(self, data: bytes, structure: Structure):
        """分析块中的字段"""
        # 识别块头部
        if len(data) >= 8:
            # 尝试识别大小字段
            size_field = Field(0, 4, 'length', data[0:4])
            structure.add_field(size_field)

            # 尝试识别类型字段
            type_field = Field(4, 8, 'type', data[4:8])
            structure.add_field(type_field)

            # 递归分析剩余数据
            remaining_data = data[8:]
            if remaining_data:
                self._analyze_main_structure(remaining_data, structure)

    def _identify_field_types(self, structure: Structure):
        """识别字段类型"""
        for field in structure.get_all_fields():
            if field.field_type == 'unknown':
                # 基于字段值和上下文推断类型
                inferred_type = self._infer_field_type(field, structure)
                if inferred_type:
                    field.field_type = inferred_type

        for child in structure.children:
            self._identify_field_types(child)

    def _infer_field_type(self, field: Field, structure: Structure) -> Optional[str]:
        """推断字段类型"""
        if not field.value:
            return None

        # 检查是否是ASCII字符串
        if all(32 <= b <= 126 for b in field.value):
            return 'string'

        # 检查是否是数值类型
        for type_name, patterns in self.type_patterns.items():
            for size, fmt in patterns:
                if len(field.value) == size:
                    try:
                        value = struct.unpack(fmt, field.value)[0]
                        if self._is_valid_value(value, type_name):
                            return type_name
                    except:
                        continue

        return None

    def _analyze_dependencies(self, structure: Structure):
        """分析依赖关系"""
        fields = structure.get_all_fields()

        # 分析长度依赖
        for field in fields:
            if field.field_type == 'length':
                # 查找可能依赖此长度的数据区域
                value = self._parse_number(field.value)
                if value:
                    end_pos = field.end + value
                    dependent_fields = [
                        f for f in fields
                        if f.start >= field.end and f.end <= end_pos
                    ]
                    for dep_field in dependent_fields:
                        if dep_field != field:
                            dep_field.dependencies.append(f'length_{field.start}')

        # 分析偏移依赖
        for field in fields:
            if field.field_type == 'offset':
                value = self._parse_number(field.value)
                if value:
                    # 查找偏移指向的位置
                    target_fields = [
                        f for f in fields
                        if f.start == value or f.end == value
                    ]
                    for target in target_fields:
                        target.dependencies.append(f'offset_{field.start}')

        # 递归处理子结构
        for child in structure.children:
            self._analyze_dependencies(child)

    def _parse_number(self, data: bytes) -> Optional[int]:
        """解析数值"""
        if not data:
            return None

        for _, fmt in self.type_patterns['length']:
            try:
                return struct.unpack(fmt, data)[0]
            except:
                continue

        return None

    def visualize_structure(self, structure: Structure,
                            output_file: str = "structure.dot"):
        """可视化结构"""
        graph = nx.DiGraph()

        def add_nodes(struct: Structure, parent_id: Optional[str] = None):
            struct_id = f"struct_{id(struct)}"
            graph.add_node(struct_id,
                           label=f"{struct.struct_type}\n{struct.start}-{struct.end}")

            if parent_id:
                graph.add_edge(parent_id, struct_id)

            # 添加字段节点
            for field in struct.fields:
                field_id = f"field_{id(field)}"
                graph.add_node(
                    field_id,
                    label=f"{field.field_type}\n{field.start}-{field.end}"
                )
                graph.add_edge(struct_id, field_id)

                # 添加依赖关系
                for dep in field.dependencies:
                    dep_id = f"dep_{dep}"
                    if dep_id in graph:
                        graph.add_edge(field_id, dep_id, style='dashed')

            # 递归处理子结构
            for child in struct.children:
                add_nodes(child, struct_id)

        add_nodes(structure)

        # 使用graphviz绘制图形
        try:
            nx.drawing.nx_agraph.write_dot(graph, output_file)
            print(f"Structure visualization saved to {output_file}")
        except Exception as e:
            print(f"Failed to save visualization: {e}")

