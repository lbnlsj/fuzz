import random
from typing import List, Dict, Any


class StructAwareMutator:
    """结构感知变异器"""

    def __init__(self):
        self.strategies = {
            'field_level': [
                self.mutate_length,
                self.mutate_type,
                self.mutate_offset
            ],
            'structure_level': [
                self.insert_structure,
                self.delete_structure,
                self.exchange_structure
            ]
        }

    def mutate_length(self, data: bytes, field_info: Dict[str, Any]) -> bytes:
        """长度字段变异"""
        if not field_info.get('is_length'):
            return data

        start, end = field_info['start'], field_info['end']
        original_length = int.from_bytes(data[start:end], byteorder='big')

        # 随机调整长度
        new_length = max(0, original_length + random.randint(-10, 10))
        new_bytes = new_length.to_bytes(end - start, byteorder='big')

        return data[:start] + new_bytes + data[end:]

    def mutate_type(self, data: bytes, field_info: Dict[str, Any]) -> bytes:
        """类型字段变异"""
        if not field_info.get('is_type'):
            return data

        start, end = field_info['start'], field_info['end']
        valid_types = field_info.get('valid_types', [])

        if valid_types:
            new_type = random.choice(valid_types)
            return data[:start] + new_type + data[end:]
        return data

    def mutate_offset(self, data: bytes, field_info: Dict[str, Any]) -> bytes:
        """偏移量字段变异"""
        if not field_info.get('is_offset'):
            return data

        start, end = field_info['start'], field_info['end']
        original_offset = int.from_bytes(data[start:end], byteorder='big')

        # 随机调整偏移量
        new_offset = max(0, original_offset + random.randint(-10, 10))
        new_bytes = new_offset.to_bytes(end - start, byteorder='big')

        return data[:start] + new_bytes + data[end:]

    def insert_structure(self, data: bytes, structure_info: Dict[str, Any]) -> bytes:
        """插入新的结构"""
        template = structure_info.get('template')
        if not template:
            return data

        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + template + data[insert_pos:]

    def delete_structure(self, data: bytes, structure_info: Dict[str, Any]) -> bytes:
        """删除已有结构"""
        start, end = structure_info['start'], structure_info['end']
        return data[:start] + data[end:]

    def exchange_structure(self, data: bytes, structure_info: Dict[str, Any]) -> bytes:
        """交换两个结构"""
        s1_start, s1_end = structure_info['start'], structure_info['end']
        s2_start, s2_end = structure_info['target_start'], structure_info['target_end']

        if s1_start >= s2_start or s1_end >= s2_start:
            return data

        s1_data = data[s1_start:s1_end]
        s2_data = data[s2_start:s2_end]

        return (data[:s1_start] + s2_data + data[s1_end:s2_start] +
                s1_data + data[s2_end:])

    def mutate(self, data: bytes, field_info: List[Dict[str, Any]],
               structure_info: List[Dict[str, Any]]) -> bytes:
        """主变异函数"""
        # 随机选择变异级别
        mutation_level = random.choice(['field_level', 'structure_level'])

        if mutation_level == 'field_level' and field_info:
            # 随机选择一个字段进行变异
            strategy = random.choice(self.strategies['field_level'])
            field = random.choice(field_info)
            return strategy(data, field)

        elif mutation_level == 'structure_level' and structure_info:
            # 随机选择一个结构进行变异
            strategy = random.choice(self.strategies['structure_level'])
            structure = random.choice(structure_info)
            return strategy(data, structure)

        return data

