#!/usr/bin/env python
"""Sets up the logging configurations."""
import logging
import logging.config
from logging.handlers import RotatingFileHandler

# Global variables
LOGGER = logging.getLogger(__name__)


def setup_logging(log_file_path: str, log_level: str):
    """
    Set up logging configuration.

    Args:
        log_file_path (str): The path to the log file.
        log_level (str): The desired log level.

    Returns:
        None
    """
    # Create file handler for logging
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=1024 * 1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s][%(asctime)s][%(process)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))

    # Create console handler for logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level.upper())
    console_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s] %(message)s'))

    # Add handlers to the logger
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console_handler)
    LOGGER.setLevel(logging.DEBUG)

    if log_level != 'INFO':
        LOGGER.log(logging.INFO, 'Log level set to %s', log_level)


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
