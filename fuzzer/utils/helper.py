import os
import json
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path
import subprocess
import time
import shutil
import struct


class FileHelper:
    """文件操作辅助类"""

    @staticmethod
    def read_binary(file_path: str) -> Optional[bytes]:
        """读取二进制文件"""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None

    @staticmethod
    def write_binary(file_path: str, data: bytes) -> bool:
        """写入二进制文件"""
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
            return True
        except Exception as e:
            logging.error(f"Error writing file {file_path}: {e}")
            return False

    @staticmethod
    def ensure_dir(dir_path: str) -> bool:
        """确保目录存在"""
        try:
            os.makedirs(dir_path, exist_ok=True)
            return True
        except Exception as e:
            logging.error(f"Error creating directory {dir_path}: {e}")
            return False

    @staticmethod
    def get_file_hash(file_path: str) -> Optional[str]:
        """获取文件哈希值"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return None


class ProcessHelper:
    """进程操作辅助类"""

    @staticmethod
    def run_with_timeout(cmd: List[str], timeout: int = 10,
                         env: Dict = None) -> Tuple[int, str, str]:
        """运行命令并设置超时"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env or os.environ.copy()
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return (
                process.returncode,
                stdout.decode('utf-8', errors='ignore'),
                stderr.decode('utf-8', errors='ignore')
            )
        except subprocess.TimeoutExpired:
            process.kill()
            return -1, "", "Timeout"
        except Exception as e:
            logging.error(f"Error running command {cmd}: {e}")
            return -1, "", str(e)


class DataHelper:
    """数据处理辅助类"""

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """提取字符串"""
        strings = []
        current = []

        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    @staticmethod
    def find_integer_values(data: bytes) -> List[Tuple[int, int]]:
        """查找整数值"""
        results = []
        formats = [
            ('<I', 4),  # 小端32位
            ('>I', 4),  # 大端32位
            ('<H', 2),  # 小端16位
            ('>H', 2),  # 大端16位
            ('<Q', 8),  # 小端64位
            ('>Q', 8)  # 大端64位
        ]

        for fmt, size in formats:
            for i in range(len(data) - size + 1):
                try:
                    value = struct.unpack(fmt, data[i:i + size])[0]
                    results.append((i, value))
                except:
                    continue

        return results

    @staticmethod
    def find_patterns(data: bytes, pattern: bytes) -> List[int]:
        """查找字节模式"""
        return [i for i in range(len(data))
                if data[i:i + len(pattern)] == pattern]


class LogHelper:
    """日志辅助类"""

    @staticmethod
    def setup_logger(name: str, log_file: str,
                     level=logging.INFO) -> logging.Logger:
        """设置日志记录器"""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger

    @staticmethod
    def log_exception(logger: logging.Logger, e: Exception,
                      context: str = ""):
        """记录异常"""
        logger.error(f"Exception in {context}: {str(e)}", exc_info=True)


class StatsHelper:
    """统计辅助类"""

    @staticmethod
    def calculate_stats(values: List[float]) -> Dict[str, float]:
        """计算基本统计数据"""
        if not values:
            return {
                'count': 0,
                'mean': 0.0,
                'min': 0.0,
                'max': 0.0,
                'std': 0.0
            }

        import numpy as np
        return {
            'count': len(values),
            'mean': np.mean(values),
            'min': np.min(values),
            'max': np.max(values),
            'std': np.std(values)
        }

    @staticmethod
    def save_stats(stats: Dict[str, Any], file_path: str):
        """保存统计数据"""
        with open(file_path, 'w') as f:
            json.dump(stats, f, indent=2)

    @staticmethod
    def load_stats(file_path: str) -> Dict[str, Any]:
        """加载统计数据"""
        with open(file_path, 'r') as f:
            return json.load(f)


class TimeHelper:
    """时间辅助类"""

    @staticmethod
    def get_elapsed_time(start_time: float) -> str:
        """获取经过的时间的可读表示"""
        elapsed = time.time() - start_time
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

    @staticmethod
    def format_timestamp(timestamp: float) -> str:
        """格式化时间戳"""
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


class PathHelper:
    """路径操作辅助类"""

    @staticmethod
    def get_project_root() -> Path:
        """获取项目根目录"""
        return Path(__file__).parent.parent.parent

    @staticmethod
    def create_unique_path(base_path: str, prefix: str = "",
                           extension: str = "") -> str:
        """创建唯一路径"""
        counter = 0
        while True:
            if counter == 0:
                path = f"{base_path}/{prefix}{extension}"
            else:
                path = f"{base_path}/{prefix}_{counter}{extension}"

            if not os.path.exists(path):
                return path
            counter += 1

    @staticmethod
    def cleanup_directory(dir_path: str, older_than: float = None):
        """清理目录"""
        if not os.path.exists(dir_path):
            return

        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)
            try:
                if older_than:
                    # 只删除特定时间之前的文件
                    if os.path.getmtime(item_path) < older_than:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                else:
                    # 删除所有文件
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
            except Exception as e:
                logging.error(f"Error cleaning up {item_path}: {e}")

