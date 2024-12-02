import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import List, Tuple, Dict
from dataclasses import dataclass


@dataclass
class StructurePrediction:
    """结构预测结果"""
    field_type: str
    start: int
    end: int
    confidence: float


class StructureEncoder(nn.Module):
    """输入结构编码器"""

    def __init__(self, input_size: int, hidden_size: int):
        super().__init__()
        self.embedding = nn.Embedding(256, input_size)  # 字节嵌入
        self.lstm = nn.LSTM(input_size, hidden_size,
                            batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_size * 2, hidden_size)

    def forward(self, x):
        embedded = self.embedding(x)
        output, _ = self.lstm(embedded)
        return self.fc(output)


class StructurePredictor(nn.Module):
    """结构预测器"""

    def __init__(self, hidden_size: int, num_classes: int):
        super().__init__()
        self.fc1 = nn.Linear(hidden_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, num_classes)
        self.dropout = nn.Dropout(0.1)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.dropout(x)
        return self.fc2(x)


class DeepStructureAnalyzer:
    """基于深度学习的结构分析器"""

    def __init__(self, model_path: str = None):
        # 模型配置
        self.input_size = 64
        self.hidden_size = 128
        self.num_classes = 5  # 字段类型数量

        # 初始化模型
        self.encoder = StructureEncoder(self.input_size, self.hidden_size)
        self.predictor = StructurePredictor(self.hidden_size, self.num_classes)

        # 如果有预训练模型则加载
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)

        # 字段类型映射
        self.type_mapping = {
            0: 'length',
            1: 'type',
            2: 'offset',
            3: 'payload',
            4: 'unknown'
        }

    def _load_model(self, model_path: str):
        """加载预训练模型"""
        checkpoint = torch.load(model_path)
        self.encoder.load_state_dict(checkpoint['encoder'])
        self.predictor.load_state_dict(checkpoint['predictor'])

    def _preprocess(self, data: bytes) -> torch.Tensor:
        """预处理输入数据"""
        # 将字节数据转换为张量
        return torch.tensor([x for x in data], dtype=torch.long).unsqueeze(0)

    def predict_structure(self, data: bytes) -> List[StructurePrediction]:
        """预测输入数据的结构"""
        self.encoder.eval()
        self.predictor.eval()

        # 预处理数据
        x = self._preprocess(data)

        with torch.no_grad():
            # 获取编码
            encoded = self.encoder(x)
            # 预测每个位置的字段类型
            predictions = self.predictor(encoded)
            probabilities = torch.softmax(predictions, dim=-1)

        # 解析预测结果
        predictions = predictions.squeeze(0)
        probabilities = probabilities.squeeze(0)

        results = []
        current_type = None
        start_pos = 0

        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            pred_type = self.type_mapping[pred.argmax().item()]
            confidence = prob[pred.argmax()].item()

            # 检测字段边界
            if pred_type != current_type:
                if current_type is not None:
                    results.append(StructurePrediction(
                        field_type=current_type,
                        start=start_pos,
                        end=i,
                        confidence=confidence
                    ))
                current_type = pred_type
                start_pos = i

        # 添加最后一个字段
        if current_type is not None:
            results.append(StructurePrediction(
                field_type=current_type,
                start=start_pos,
                end=len(data),
                confidence=confidence
            ))

        return results

    def train(self, training_data: List[Tuple[bytes, List[Dict]]],
              epochs: int = 10, batch_size: int = 32):
        """训练模型"""
        self.encoder.train()
        self.predictor.train()

        optimizer = optim.Adam(list(self.encoder.parameters()) +
                               list(self.predictor.parameters()))
        criterion = nn.CrossEntropyLoss()

        for epoch in range(epochs):
            total_loss = 0
            for data, labels in self._batch_generator(training_data, batch_size):
                optimizer.zero_grad()

                # 前向传播
                x = self._preprocess(data)
                encoded = self.encoder(x)
                predictions = self.predictor(encoded)

                # 计算损失
                loss = criterion(predictions.view(-1, self.num_classes),
                                 torch.tensor(labels, dtype=torch.long))

                # 反向传播
                loss.backward()
                optimizer.step()

                total_loss += loss.item()

            print(f"Epoch {epoch + 1}, Loss: {total_loss / len(training_data):.4f}")

    def _batch_generator(self, data, batch_size):
        """生成训练批次"""
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            yield zip(*batch)


class DLStructureAwareMutator:
    """结合深度学习的结构感知变异器"""

    def __init__(self, model_path: str = None):
        self.base_mutator = StructAwareMutator()
        self.dl_analyzer = DeepStructureAnalyzer(model_path)
        self.confidence_threshold = 0.8

    def mutate(self, data: bytes, field_info: List[Dict[str, Any]],
               structure_info: List[Dict[str, Any]]) -> bytes:
        """使用深度学习增强的变异"""
        # 获取深度学习模型的结构预测
        dl_predictions = self.dl_analyzer.predict_structure(data)

        # 筛选高置信度的预测
        high_confidence_fields = [
            pred for pred in dl_predictions
            if pred.confidence >= self.confidence_threshold
        ]

        # 整合预测结果和现有字段信息
        enhanced_field_info = self._merge_field_info(field_info, high_confidence_fields)

        # 使用增强后的字段信息进行变异
        return self.base_mutator.mutate(data, enhanced_field_info, structure_info)

    def _merge_field_info(self, original_fields: List[Dict],
                          dl_predictions: List[StructurePrediction]) -> List[Dict]:
        """合并原始字段信息和深度学习预测"""
        merged_fields = original_fields.copy()

        for pred in dl_predictions:
            # 检查是否与现有字段重叠
            overlap = False
            for field in original_fields:
                if (pred.start < field['end'] and pred.end > field['start']):
                    overlap = True
                    break

            # 如果没有重叠，添加新字段
            if not overlap:
                merged_fields.append({
                    'start': pred.start,
                    'end': pred.end,
                    'type': pred.field_type,
                    'confidence': pred.confidence
                })

        return merged_fields

