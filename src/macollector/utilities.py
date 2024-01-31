#!/usr/bin/env python
"""
utilities.py: Utility functions for the application.

This module contains utility functions and decorators used across the
application, including logging decorators, runtime monitoring, and
safe script exit functionalities.

It leverages the standard logging and functools modules, providing
enhanced logging and performance measurement capabilities.
"""

import functools
import logging
import sys
import time
from datetime import datetime
from typing import Any, Callable, Optional

# Local imports
from .logging_setup import add_separator_to_log

# Shared logger
logger = logging.getLogger('macollector')


def debug_log(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to log the function call and its return value.

    This decorator logs the entry and exit of the function with detailed
    information about the arguments and the return value.

    :param func: Function to be decorated.
    :type func: Callable[..., Any]
    :return: Wrapped function.
    :rtype: Callable[..., Any]
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        arguments = [repr(a) for a in args]
        keyword_arguments = [f'{k}={v!r}' for k, v in kwargs.items()]
        signature = ', '.join(arguments + keyword_arguments)
        logger.debug('Calling %s(%s)', func.__name__, signature)
        result = func(*args, **kwargs)
        logger.debug('%s() returned %r', func.__name__, result)
        return result

    return wrapper


def runtime_monitor(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to measure and log the runtime of a function.

    This decorator calculates and logs the execution time of the function,
    aiding in performance monitoring.

    :param func: Function to be decorated.
    :type func: Callable[..., Any]
    :return: Wrapped function.
    :rtype: Callable[..., Any]
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed_time = time.perf_counter() - start_time
        logger.debug('%s() executed in %0.2f seconds.',
                     func.__name__, elapsed_time)
        return result

    return wrapper


def safe_exit(
        device_counter: int = 0,
        listener=None,
        log_file_path: str = '.\\logs\\config.json',
        script_start_timer: Optional[float] = None,
) -> None:
    """
    Safely exits the script with proper logging and cleanup.

    Logs the total script execution time and number of devices processed.
    Stops the logging listener if present and adds a separator to the log file.
    Finally, exits the script.

    :param device_counter: Number of devices processed.
    :type device_counter: int
    :param listener: Logging listener to be stopped.
    :param log_file_path: Path to the log file for adding a separator.
    :type log_file_path: str
    :param script_start_timer: Start time of the script, for calculating total runtime.
    :type script_start_timer: Optional[float]
    """
    if script_start_timer and device_counter != 0:
        # Get and log finishing time
        script_elapsed_time = time.perf_counter() - script_start_timer
        logger.info('The script required %0.2f seconds to finish processing on'
                    ' %d devices.', script_elapsed_time, device_counter)
        logger.info("Script execution completed: %s",
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Stop the logging listener if it exists
    if listener:
        listener.stop()

    # Add a separator to the log file
    add_separator_to_log(log_file_path)

    # Exit the script
    sys.exit()
