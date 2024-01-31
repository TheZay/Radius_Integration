#!/usr/bin/env python
"""
logging_setup.py: Configure logging for the application.

This module configures the logging for the application. It sets up file
and console log handlers, a logging queue for asynchronous logging, and
formats the log messages. It supports setting different log levels and
rotates log files when they reach a certain size.

The module provides a `setup_logging` function to initialize logging and
`add_separator_to_log` to add separators in log files for better readability.
"""

import logging
import logging.config
from logging.handlers import QueueListener, RotatingFileHandler
from queue import Queue


def setup_logging(log_file_path: str, log_level: str = 'INFO'):
    """
    Initialize logging with file and console handlers.

    Sets up logging with both file and console handlers. Log messages are
    formatted and logged asynchronously. Supports log rotation and different
    log levels.

    :param log_file_path: Path to the log file.
    :type log_file_path: str
    :param log_level: Logging level ('DEBUG', 'INFO', etc.). Defaults to 'INFO'.
    :type log_level: str
    :return: Tuple containing the logger and the queue listener.
    :rtype: tuple
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
        log_queue,  # Queue
        file_handler, console_handler,  # Handlers
        respect_handler_level=True
    )

    # Start the queue listener
    listener.start()

    if log_level != 'INFO':
        logger.log(logging.INFO, 'Log level set to %s', log_level)

    return logger, listener


def add_separator_to_log(log_file_path: str, separator: str = '-' * 80):
    """
    Add a separator line to the log file.

    Writes a separator line to the end of the specified log file. Useful for
    delineating log entries.

    :param log_file_path: Path to the log file.
    :type log_file_path: str
    :param separator: Separator string to add to the log file.
    :type separator: str
    """
    with open(log_file_path, 'a', encoding="utf-8") as log_file:
        log_file.write(separator + '\n')
