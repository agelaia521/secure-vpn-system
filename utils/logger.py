"""
日志工具模块
提供统一的日志记录功能
"""

import logging
import sys
from datetime import datetime


class Logger:
    """统一日志记录器"""

    def __init__(self, name: str, level: int = logging.INFO):
        """
        初始化日志记录器
        :param name: 日志记录器名称
        :param level: 日志级别
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # 避免重复添加handler
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(level)

            formatter = logging.Formatter(
                fmt='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, msg: str):
        self.logger.info(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def debug(self, msg: str):
        self.logger.debug(msg)


def setup_logger(name: str, level: int = logging.INFO) -> Logger:
    """
    创建日志记录器
    :param name: 日志记录器名称
    :param level: 日志级别
    :return: Logger实例
    """
    return Logger(name, level)
