import logging

from uaclient.defaults import DEFAULT_LOG_FORMAT


def setup_logging(logger, log_level, log_file):
    logger.setLevel(log_level)

    logger.handlers = []

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))
    file_handler.set_name("ua-file")
    logger.addHandler(file_handler)
