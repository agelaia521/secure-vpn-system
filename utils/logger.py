"""
日志工具模块
提供统一的日志记录功能，支持彩色输出
"""

import logging
import sys
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """带颜色的日志格式化器"""
    
    # ANSI转义序列颜色代码
    COLORS = {
        'RESET': '\033[0m',
        'BLACK': '\033[30m',
        'RED': '\033[31m',
        'GREEN': '\033[32m',
        'YELLOW': '\033[33m',
        'BLUE': '\033[34m',
        'MAGENTA': '\033[35m',
        'CYAN': '\033[36m',
        'WHITE': '\033[37m',
        
        'BOLD_RED': '\033[1;31m',
        'BOLD_GREEN': '\033[1;32m',
        'BOLD_YELLOW': '\033[1;33m',
        'BOLD_BLUE': '\033[1;34m',
        'BOLD_MAGENTA': '\033[1;35m',
        'BOLD_CYAN': '\033[1;36m',
    }
    
    # 日志级别颜色映射
    LEVEL_COLORS = {
        logging.DEBUG: COLORS['CYAN'],
        logging.INFO: COLORS['GREEN'],
        logging.WARNING: COLORS['YELLOW'],
        logging.ERROR: COLORS['RED'],
    }
    
    # 模块名称颜色映射
    MODULE_COLORS = {
        'VPN_Server': COLORS['BOLD_BLUE'],
        'VPN_Client': COLORS['BOLD_MAGENTA'],
        'Network_VPN_Server': COLORS['BOLD_CYAN'],
        'Network_VPN_Client': COLORS['BOLD_GREEN'],
    }
    
    def format(self, record):
        # 获取级别颜色
        level_color = self.LEVEL_COLORS.get(record.levelno, self.COLORS['WHITE'])
        level_name = record.levelname
        
        # 获取模块颜色
        module_color = self.MODULE_COLORS.get(record.name, self.COLORS['WHITE'])
        module_name = record.name
        
        # 格式化时间
        time_str = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # 构建彩色日志行
        log_line = (
            f"{self.COLORS['BLACK']}[{time_str}]{self.COLORS['RESET']} "
            f"{module_color}[{module_name}]{self.COLORS['RESET']} "
            f"{level_color}[{level_name}]{self.COLORS['RESET']} "
            f"{self.COLORS['WHITE']}{record.getMessage()}{self.COLORS['RESET']}"
        )
        
        return log_line


class Logger:
    """统一日志记录器，支持彩色输出"""

    def __init__(self, name: str, level: int = logging.INFO, color=True):
        """
        初始化日志记录器
        :param name: 日志记录器名称
        :param level: 日志级别
        :param color: 是否启用彩色输出
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False

        # 避免重复添加handler
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(level)

            if color and sys.stdout.isatty():
                formatter = ColorFormatter()
            else:
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
    
    def success(self, msg: str):
        """成功消息，使用绿色"""
        print(f"\033[1;32m[SUCCESS] {msg}\033[0m")


def setup_logger(name: str, level: int = logging.INFO) -> Logger:
    """
    创建日志记录器
    :param name: 日志记录器名称
    :param level: 日志级别
    :return: Logger实例
    """
    return Logger(name, level)