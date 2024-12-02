import numpy as np
from typing import List, Dict, Any
from collections import defaultdict
import random


class MutationHistory:
    """记录变异历史"""

    def __init__(self):
        self.history = []
        self.strategy_stats = defaultdict(lambda: {'success': 0, 'total': 0})

    def add_record(self, strategy: str, success: bool):
        """添加一条变异记录"""
        self.history.append((strategy, success))
        self.strategy_stats[strategy]['total'] += 1
        if success:
            self.strategy_stats[strategy]['success'] += 1

    def get_success_rate(self, strategy: str) -> float:
        """获取策略的成功率"""
        stats = self.strategy_stats[strategy]
        if stats['total'] == 0:
            return 0.0
        return stats['success'] / stats['total']


class AdaptiveMutator:
    """自适应变异器"""

    def __init__(self):
        self.history = MutationHistory()
        self.learning_rate = 0.1
        self.exploration_rate = 0.2

        # 初始化策略权重
        self.strategy_weights = {
            'field_level': {
                'mutate_length': 1.0,
                'mutate_type': 1.0,
                'mutate_offset': 1.0
            },
            'structure_level': {
                'insert_structure': 1.0,
                'delete_structure': 1.0,
                'exchange_structure': 1.0
            }
        }

    def update_weights(self):
        """更新策略权重"""
        for category in self.strategy_weights:
            for strategy in self.strategy_weights[category]:
                success_rate = self.history.get_success_rate(strategy)
                # 使用指数移动平均更新权重
                self.strategy_weights[category][strategy] = (
                        (1 - self.learning_rate) * self.strategy_weights[category][strategy] +
                        self.learning_rate * success_rate
                )

    def select_strategy(self, level: str) -> str:
        """选择变异策略"""
        if random.random() < self.exploration_rate:
            # 探索：随机选择策略
            return random.choice(list(self.strategy_weights[level].keys()))
        else:
            # 利用：根据权重选择策略
            weights = list(self.strategy_weights[level].values())
            strategies = list(self.strategy_weights[level].keys())
            return random.choices(strategies, weights=weights)[0]


class AdaptiveStructAwareMutator:
    """自适应结构感知变异器"""

    def __init__(self):
        self.adaptive_mutator = AdaptiveMutator()
        self.base_mutator = StructAwareMutator()  # 基础变异器

    def mutate(self, data: bytes, field_info: List[Dict[str, Any]],
               structure_info: List[Dict[str, Any]]) -> bytes:
        """主变异函数"""
        # 选择变异级别
        mutation_level = random.choice(['field_level', 'structure_level'])

        # 根据自适应策略选择具体的变异方法
        strategy = self.adaptive_mutator.select_strategy(mutation_level)

        # 执行变异
        if mutation_level == 'field_level' and field_info:
            field = random.choice(field_info)
            mutated_data = getattr(self.base_mutator, strategy)(data, field)
        elif mutation_level == 'structure_level' and structure_info:
            structure = random.choice(structure_info)
            mutated_data = getattr(self.base_mutator, strategy)(data, structure)
        else:
            return data

        return mutated_data

    def update_history(self, strategy: str, success: bool):
        """更新变异历史"""
        self.adaptive_mutator.history.add_record(strategy, success)
        self.adaptive_mutator.update_weights()

    def get_strategy_weights(self) -> Dict[str, Dict[str, float]]:
        """获取当前策略权重"""
        return self.adaptive_mutator.strategy_weights
