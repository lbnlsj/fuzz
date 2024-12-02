import pytest
import torch
import numpy as np
from fuzzer.core.adaptive_mutation import AdaptiveStructAwareMutator
from fuzzer.analysis.dl_structure import DeepStructureAnalyzer, DLStructureAwareMutator


class TestAdaptiveMutation:
    """测试自适应变异策略"""

    @pytest.fixture
    def mutator(self):
        return AdaptiveStructAwareMutator()

    def test_strategy_selection(self, mutator):
        """测试策略选择"""
        # 初始状态下所有策略权重应该相等
        weights = mutator.get_strategy_weights()
        for level in weights:
            unique_weights = set(weights[level].values())
            assert len(unique_weights) == 1
            assert list(unique_weights)[0] == 1.0

    def test_weight_update(self, mutator):
        """测试权重更新"""
        # 模拟一些成功和失败的变异
        strategies = ['mutate_length', 'mutate_type']
        results = [
            ('mutate_length', True),
            ('mutate_length', True),
            ('mutate_type', False)
        ]

        # 更新历史记录
        for strategy, success in results:
            mutator.adaptive_mutator.history.add_record(strategy, success)

        # 更新权重
        mutator.adaptive_mutator.update_weights()

        # 检查权重更新是否合理
        weights = mutator.get_strategy_weights()
        assert weights['field_level']['mutate_length'] > weights['field_level']['mutate_type']

    def test_adaptive_mutation(self, mutator):
        """测试自适应变异过程"""
        data = b"TEST1234"
        field_info = [{
            'start': 0,
            'end': 4,
            'is_type': True,
            'valid_types': [b"TEST", b"DEMO"]
        }]
        structure_info = []

        # 执行多次变异
        results = []
        for _ in range(10):
            mutated = mutator.mutate(data, field_info, structure_info)
            results.append(mutated)

        # 确保产生了变异
        assert len(set(results)) > 1


class TestDeepLearningStructure:
    """测试基于深度学习的结构分析"""

    @pytest.fixture
    def analyzer(self):
        return DeepStructureAnalyzer()

    @pytest.fixture
    def mutator(self):
        return DLStructureAwareMutator()

    def test_model_architecture(self, analyzer):
        """测试模型架构"""
        # 检查编码器
        assert isinstance(analyzer.encoder.embedding, torch.nn.Embedding)
        assert isinstance(analyzer.encoder.lstm, torch.nn.LSTM)
        assert isinstance(analyzer.encoder.fc, torch.nn.Linear)

        # 检查预测器
        assert isinstance(analyzer.predictor.fc1, torch.nn.Linear)
        assert isinstance(analyzer.predictor.fc2, torch.nn.Linear)

    def test_structure_prediction(self, analyzer):
        """测试结构预测"""
        # 准备测试数据
        data = b"TYPE\x00\x00\x00\x0APAYLOAD123"

        # 执行预测
        predictions = analyzer.predict_structure(data)

        # 验证预测结果
        assert len(predictions) > 0
        for pred in predictions:
            assert 0 <= pred.start < len(data)
            assert 0 <= pred.end <= len(data)
            assert pred.confidence >= 0 and pred.confidence <= 1
            assert pred.field_type in analyzer.type_mapping.values()

    def test_training_process(self, analyzer):
        """测试模型训练过程"""
        # 准备训练数据
        training_data = [
            (b"TYPE\x00\x00\x00\x0A", [{'type': 'type', 'start': 0, 'end': 4}]),
            (b"SIZE\x00\x00\x00\x0B", [{'type': 'length', 'start': 0, 'end': 4}])
        ]

        # 执行训练
        try:
            analyzer.train(training_data, epochs=2, batch_size=1)
            trained = True
        except:
            trained = False

        assert trained

    def test_dl_enhanced_mutation(self, mutator):
        """测试深度学习增强的变异"""
        data = b"TYPE\x00\x00\x00\x0APAYLOAD123"
        field_info = [{
            'start': 0,
            'end': 4,
            'is_type': True,
            'valid_types': [b"TYPE", b"SIZE"]
        }]
        structure_info = []

        # 执行变异
        mutated = mutator.mutate(data, field_info, structure_info)

        # 验证结果
        assert isinstance(mutated, bytes)
        assert len(mutated) > 0
        assert mutated != data


class TestComparison:
    """比较不同方法的性能"""

    @pytest.fixture
    def sample_program(self):
        """创建一个简单的测试程序"""
        source = """
        #include <stdio.h>
        #include <string.h>

        int main(int argc, char** argv) {
            FILE* f = fopen(argv[1], "rb");
            if (!f) return 1;

            char buf[100];
            size_t n = fread(buf, 1, sizeof(buf), f);
            fclose(f);

            if (n >= 4) {
                if (memcmp(buf, "TYPE", 4) == 0) {
                    if (n >= 8 && buf[7] == 'A') {
                        // 路径1
                        return 0;
                    }
                } else if (memcmp(buf, "SIZE", 4) == 0) {
                    if (n >= 8 && buf[7] == 'B') {
                        // 路径2
                        return 0;
                    }
                }
            }
            return 1;
        }
        """

        # 编译测试程序
        with open("test_compare.c", "w") as f:
            f.write(source)
        os.system("gcc test_compare.c -o test_compare")

        yield "./test_compare"

        # 清理
        os.remove("test_compare.c")
        os.remove("test_compare")

    def test_coverage_comparison(self, sample_program):
        """比较不同方法的覆盖率"""
        # 初始化三种fuzzer
        fuzzers = {
            'baseline': EnhancedStructAwareFuzzer(
                sample_program, "corpus", "output_baseline", "baseline"
            ),
            'adaptive': EnhancedStructAwareFuzzer(
                sample_program, "corpus", "output_adaptive", "adaptive"
            ),
            'deep_learning': EnhancedStructAwareFuzzer(
                sample_program, "corpus", "output_dl", "deep_learning"
            )
        }

        # 准备初始语料库
        os.makedirs("corpus", exist_ok=True)
        with open("corpus/seed", "wb") as f:
            f.write(b"TYPE\x00\x00\x00\x00")

        results = {}

        # 运行每种fuzzer
        for name, fuzzer in fuzzers.items():
            fuzzer.run(max_iterations=1000)
            results[name] = {
                'coverage': fuzzer.coverage.get_total_coverage(),
                'crashes': len(fuzzer.unique_crashes),
                'corpus_size': len(fuzzer.corpus)
            }

        # 清理
        import shutil
        shutil.rmtree("corpus")
        shutil.rmtree("output_baseline")
        shutil.rmtree("output_adaptive")
        shutil.rmtree("output_dl")

        # 验证结果
        # 自适应和深度学习方法应该比基准方法效果好
        assert results['adaptive']['coverage'] >= results['baseline']['coverage']
        assert results['deep_learning']['coverage'] >= results['baseline']['coverage']
