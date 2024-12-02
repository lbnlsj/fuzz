import subprocess
import os
import signal
from typing import Tuple, Optional
import time


class Executor:
    """程序执行器"""

    def __init__(self, target_path: str, timeout: int = 1):
        self.target_path = target_path
        self.timeout = timeout

    def run_target(self, input_data: bytes,
                   temp_file: str = "temp_input") -> Tuple[int, Optional[str]]:
        """
        运行目标程序
        返回: (返回码, 错误信息)
        """
        # 将输入数据写入临时文件
        with open(temp_file, 'wb') as f:
            f.write(input_data)

        try:
            # 启动进程
            process = subprocess.Popen(
                [self.target_path, temp_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )

            # 等待进程完成或超时
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                return process.returncode, stderr.decode('utf-8', errors='ignore')
            except subprocess.TimeoutExpired:
                # 如果超时，终止进程组
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                return -1, "Timeout"

        except Exception as e:
            return -1, str(e)
        finally:
            # 清理临时文件
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def is_crash(self, return_code: int) -> bool:
        """
        判断是否发生崩溃
        """
        return return_code < 0 or return_code == 139  # SIGSEGV

    def get_crash_info(self, error_msg: str) -> str:
        """
        解析崩溃信息
        """
        # 简单的崩溃信息提取
        crash_indicators = [
            "SIGSEGV",
            "segmentation fault",
            "stack overflow",
            "buffer overflow",
            "memory corruption",
            "heap corruption"
        ]

        found_indicators = []
        error_msg = error_msg.lower()

        for indicator in crash_indicators:
            if indicator in error_msg:
                found_indicators.append(indicator)

        return " | ".join(found_indicators) if found_indicators else "Unknown crash"


class ExecutionResult:
    """执行结果"""

    def __init__(self, return_code: int, error_msg: str,
                 execution_time: float):
        self.return_code = return_code
        self.error_msg = error_msg
        self.execution_time = execution_time
        self.is_crash = return_code < 0 or return_code == 139

    @property
    def crash_info(self):
        if not self.is_crash:
            return None

        # 解析崩溃信息
        if "SIGSEGV" in self.error_msg:
            return "Segmentation Fault"
        elif "timeout" in self.error_msg.lower():
            return "Timeout"
        else:
            return "Unknown Crash"
