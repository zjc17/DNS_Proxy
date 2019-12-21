# -*- coding: utf-8 -*-
'''
全局日志配置
Reference: https://blog.phpgao.com/python_colorful_log.html
'''
import logging

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
#The background is set with 40 plus the number of the color, and the foreground with 30
#These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"
COLORS = {
    'DEBUG': BLUE,
    'INFO': GREEN,
    'WARNING': YELLOW,
    'ERROR': MAGENTA,
    'CRITICAL': RED
}

def formatter_message(message, use_color=True):
    '''
    日志消息格式化器
    '''
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message

class ColoredFormatter(logging.Formatter):
    '''
    自定义Formatter
    '''
    def __init__(self, msg, datefmt, use_color=True):
        '''
        初始化
        '''
        logging.Formatter.__init__(self, fmt=msg, datefmt=datefmt)
        self.use_color = use_color

    def format(self, record):
        '''
        生成格式化后的日志消息
        '''
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)

class ColoredLogger(logging.Logger):
    '''
    Custom logger class with multiple destinations
    '''
    FORMAT = '%(asctime)s %(levelname)-20s %(message)s($BOLD%(filename)s$RESET:%(lineno)d)'
    COLOR_FORMAT = formatter_message(FORMAT, True)

    def __init__(self, _name):
        '''
        初始化
        '''
        logging.Logger.__init__(self, _name, logging.DEBUG)
        color_formatter = ColoredFormatter(self.COLOR_FORMAT, datefmt='%H:%M:%S')
        console = logging.StreamHandler()
        console.setFormatter(color_formatter)
        self.addHandler(console)

def create_logger(name, level=logging.DEBUG):
    '''
    创建日志器
    '''
    logging.setLoggerClass(ColoredLogger)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger

if __name__ == '__main__':
    logging.setLoggerClass(ColoredLogger)
    COLOR_LOG = logging.getLogger(__name__)
    COLOR_LOG.setLevel(logging.DEBUG)
    COLOR_LOG.debug("test")
    COLOR_LOG.info("test")
    COLOR_LOG.warning("test")
    COLOR_LOG.error("test")
    COLOR_LOG.critical("test")
