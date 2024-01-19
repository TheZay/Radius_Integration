#!/usr/bin/env python
"""Sets up the logging configurations."""
import logging
import logging.config
from logging.handlers import RotatingFileHandler, QueueListener
from queue import Queue


def setup_logging(log_file_path: str, log_level: str = 'INFO'):
    """
    Set up logging configuration.

    Args:
        log_file_path (str): The path to the log file.
        log_level (str): The desired log level.

    Returns:
        None
    """
    # Create a logger
    logger = logging.getLogger('macollector')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Create file handler for logging
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=1024 * 1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s][%(asctime)s][%(threadName)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))

    # Create console handler for logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.getLevelName(log_level.upper()))
    console_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s] %(message)s'))

    # Add handlers directly to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Set up a log queue for handling logs asynchronously
    log_queue = Queue(-1)
    listener = QueueListener(
        log_queue, file_handler, console_handler, respect_handler_level=True)

    # Start the queue listener
    listener.start()

    if log_level != 'INFO':
        logger.log(logging.INFO, 'Log level set to %s', log_level)

    return logger, listener


def add_separator_to_log(log_file_path: str, separator: str = '-' * 80):
    """
    Add a separator to the end of the log file.

    Args:
        log_file_path (str): The path to the log file.
        separator (str): The separator string to add.

    Returns:
        None
    """
    with open(log_file_path, 'a', encoding="utf-8") as log_file:
        log_file.write(separator + '\n')
