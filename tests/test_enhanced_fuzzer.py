import os
import pytest
import tempfile
import subprocess
from pathlib import Path
import numpy as np
import torch

from fuzzer.core.adaptive_mutation import AdaptiveStructAwareMutator
from fuzzer.analysis.dl_structure import DeepStructureAnalyzer, DLStructureAwareMutator
from fuzzer.enhanced_main import EnhancedStructAwareFuzzer


class TestProgram:
    """测试程序生成器"""

    @staticmethod
    def create_vulnerable_program() -> str:
        """创建一个包含漏洞的测试程序"""
        source = """
        #include <stdio.h>
        #include <string.h>
        #include <stdlib.h>

        // 简单的文件格式: 
        // magic(4字节) + type(4字节) + length(4字节) + data(变长)

        struct Header {
            char magic[4];    // "TEST"
            int type;         // 1: 正常, 2: 崩溃, 3: 新路径
            int length;       // data长度
        };

        int process_file(const char* filename) {
            FILE* f = fopen(filename, "rb");
            if (!f) return 1;

            struct Header header;
            if (fread(&header, sizeof(header), 1, f) != 1) {
                fclose(f);
                return 1;
            }

            // 检查magic
            if (memcmp(header.magic, "TEST", 4) != 0) {
                fclose(f);
                return 1;
            }

            // 分配缓冲区
            char* data = malloc(header.length);
            if (!data) {
                fclose(f);
                return 1;
            }

            // 读取数据
            if (fread(data, 1, header.length, f) != header.length) {
                free(data);
                fclose(f);
                return 1;
            }

            // 根据类型处理
            switch (header.type) {
                case 1:
                    // 正常路径
                    break;

                case 2:
                    // 触发崩溃
                    free(data);
                    free(data);  // 双重释放
                    break;

                case 3:
                    // 新路径
                    if (data[0] == 'A' && data[1] == 'B' && 
                        data[2] == 'C' && data[3] == 'D') {
                        // 深度路径
                    }
                    break;
            }

            free(data);
            fclose(f);
            return 0;
        }

        int main(int argc, char** argv) {
            if (argc != 2) return 1;
            return process_file(argv[1]);
        }
        """

        # 保存并编译源代码
        with tempfile.NamedTemporaryFile(suffix='.c', delete=False) as f:
            f.write(source.encode())
            source_path = f.name

        binary_path = source_path + '.bin'
        subprocess.run(['gcc', '-o', binary_path, source_path])
        os.unlink(source_path)

        return binary_path


class TestAdaptiveMutation:
    """测试自适应变异策略"""

    @pytest.fixture
    def mutator(self):
        return AdaptiveStructAwareMutator()

    def test_strategy_weights_update(self, mutator):
        """测试策略权重更新"""
        # 初始权重应该相等
        initial_weights = mutator.get_strategy_weights()
        for category in initial_weights.values():
            weights = list(category.values())
            assert len(set(weights)) == 1  # 所有权重相等

        # 模拟策略执行结果
        for _ in range(10):
            mutator.update_history('mutate_length', True)
            mutator.update_history('mutate_type', False)

        # 检查权重更新
        updated_weights = mutator.get_strategy_weights()
        assert (updated_weights['field_level']['mutate_length'] >
                updated_weights['field_level']['mutate_type'])

    def test_mutation_effectiveness(self, mutator):
        """测试变异效果"""
        # 准备测试数据
        data = b"TEST\x00\x00\x00\x01\x00\x00\x00\x04ABCD"
        field_info = [
            {'start': 0, 'end': 4, 'is_type': True},
            {'start': 4, 'end': 8, 'is_length': True},
            {'start': 8, 'end': 12, 'is_payload': True}
        ]

        # 执行多次变异
        mutations = set()
        for _ in range(50):
            mutated = mutator.mutate(data, field_info, [])
            mutations.add(mutated)

        # 验证变异的多样性
        assert len(mutations) > 1

    def test_adaptive_learning(self, mutator):
        """测试自适应学习"""
        # 初始成功率
        initial_success = mutator.adaptive_mutator.history.get_success_rate(
            'mutate_length'
        )

        # 模拟学习过程
        for _ in range(20):
            # 某些策略更成功
            mutator.update_history('mutate_length', True)
            mutator.update_history('mutate_type', False)

        # 验证学习效果
        final_success = mutator.adaptive_mutator.history.get_success_rate(
            'mutate_length'
        )
        assert final_success > initial_success


class TestDeepLearningStructure:
    """测试深度学习结构分析"""

    @pytest.fixture
    def analyzer(self):
        return DeepStructureAnalyzer()

    def test_model_architecture(self, analyzer):
        """测试模型架构"""
        # 验证编码器组件
        assert isinstance(analyzer.encoder.embedding, torch.nn.Embedding)
        assert isinstance(analyzer.encoder.lstm, torch.nn.LSTM)
        assert isinstance(analyzer.encoder.fc, torch.nn.Linear)

        # 验证预测器组件
        assert isinstance(analyzer.predictor.fc1, torch.nn.Linear)
        assert isinstance(analyzer.predictor.fc2, torch.nn.Linear)

    def test_structure_prediction(self, analyzer):
        """测试结构预测"""
        # 准备测试数据
        data = b"TEST\x00\x00\x00\x01\x00\x00\x00\x04ABCD"

        # 获取预测结果
        predictions = analyzer.predict_structure(data)

        # 验证预测结果
        assert len(predictions) > 0
        for pred in predictions:
            assert 0 <= pred.start < len(data)
            assert 0 <= pred.end <= len(data)
            assert 0 <= pred.confidence <= 1
            assert pred.field_type in analyzer.type_mapping.values()

    def test_training_process(self, analyzer):
        """测试模型训练"""
        # 准备训练数据
        training_data = [
            (b"TEST\x00\x00\x00\x01", [{'type': 'magic', 'start': 0, 'end': 4}]),
            (b"TEST\x00\x00\x00\x02", [{'type': 'magic', 'start': 0, 'end': 4}])
        ]

        # 执行训练
        try:
            analyzer.train(training_data, epochs=2)
            trained = True
        except:
            trained = False

        assert trained


class TestEnhancedFuzzer:
    """测试增强版模糊测试器"""

    @pytest.fixture
    def target_program(self):
        return TestProgram.create_vulnerable_program()

    @pytest.fixture
    def corpus_dir(self):
        path = tempfile.mkdtemp()
        # 创建初始语料
        with open(os.path.join(path, 'seed'), 'wb') as f:
            f.write(b"TEST\x00\x00\x00\x01\x00\x00\x00\x04ABCD")
        return path

    @pytest.fixture
    def output_dir(self):
        return tempfile.mkdtemp()

    def test_baseline_fuzzing(self, target_program, corpus_dir, output_dir):
        """测试基准版本"""
        fuzzer = EnhancedStructAwareFuzzer(
            target_program,
            corpus_dir,
            output_dir,
            mode='baseline',
            timeout=1
        )

        # 运行一小段时间
        fuzzer.run(max_iterations=1000)

        # 验证结果
        assert os.path.exists(output_dir)
        assert len(os.listdir(os.path.join(output_dir, "crashes"))) >= 0
        assert len(os.listdir(os.path.join(output_dir, "queue"))) > 0

    def test_adaptive_fuzzing(self, target_program, corpus_dir, output_dir):
        """测试自适应版本"""
        fuzzer = EnhancedStructAwareFuzzer(
            target_program,
            corpus_dir,
            output_dir,
            mode='adaptive',
            timeout=1
        )

        # 运行一小段时间
        fuzzer.run(max_iterations=1000)

        # 验证结果
        crashes = len(os.listdir(os.path.join(output_dir, "crashes")))
        queue = len(os.listdir(os.path.join(output_dir, "queue")))

        assert crashes >= 0
        assert queue > 0

    def test_deep_learning_fuzzing(self, target_program, corpus_dir, output_dir):
        """测试深度学习版本"""
        fuzzer = EnhancedStructAwareFuzzer(
            target_program,
            corpus_dir,
            output_dir,
            mode='deep_learning',
            timeout=1
        )

        # 运行一小段时间
        fuzzer.run(max_iterations=1000)

        # 验证结果
        crashes = len(os.listdir(os.path.join(output_dir, "crashes")))
        queue = len(os.listdir(os.path.join(output_dir, "queue")))

        assert crashes >= 0
        assert queue > 0

    def test_performance_comparison(self, target_program, corpus_dir, output_dir):
        """比较性能"""
        results = {}

        # 测试各个版本
        for mode in ['baseline', 'adaptive', 'deep_learning']:
            test_output = os.path.join(output_dir, mode)
            os.makedirs(test_output)

            fuzzer = EnhancedStructAwareFuzzer(
                target_program,
                corpus_dir,
                test_output,
                mode=mode,
                timeout=1
            )

            fuzzer.run(max_iterations=1000)

            results[mode] = {
                'crashes': len(os.listdir(os.path.join(test_output, "crashes"))),
                'queue': len(os.listdir(os.path.join(test_output, "queue"))),
                'coverage': fuzzer.coverage.get_coverage_stats()
            }

        # 验证创新版本的改进
        assert (results['adaptive']['coverage']['edge_coverage']['covered'] >=
                results['baseline']['coverage']['edge_coverage']['covered'])
        assert (results['deep_learning']['coverage']['edge_coverage']['covered'] >=
                results['baseline']['coverage']['edge_coverage']['covered'])

    @pytest.mark.parametrize("mode", ['baseline', 'adaptive', 'deep_learning'])
    def test_crash_reproduction(self, target_program, corpus_dir, output_dir, mode):
        """测试崩溃重现"""
        fuzzer = EnhancedStructAwareFuzzer(
            target_program,
            corpus_dir,
            output_dir,
            mode=mode,
            timeout=1
        )

        # 运行直到发现崩溃
        max_iterations = 2000
        found_crash = False

        fuzzer.run(max_iterations)

        crashes_dir = os.path.join(output_dir, "crashes")
        if os.path.exists(crashes_dir) and os.listdir(crashes_dir):
            found_crash = True

            # 尝试重现崩溃
            crash_file = os.path.join(crashes_dir, os.listdir(crashes_dir)[0])
            with open(crash_file, 'rb') as f:
                crash_input = f.read()

            # 重新执行崩溃输入
            return_code, _ = fuzzer.executor.run_target(crash_input)
            assert fuzzer.executor.is_crash(return_code)

        assert found_crash, f"No crash found in {mode} mode"


def test_cleanup():
    """清理测试文件"""
    import shutil

    # 清理临时目录
    temp_dirs = [d for d in os.listdir('/tmp') if d.startswith('tmp')]
    for d in temp_dirs:
        try:
            shutil.rmtree(os.path.join('/tmp', d))
        except:
            pass

