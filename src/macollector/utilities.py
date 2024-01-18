#!/usr/bin/env python
"""Utility functions for the application."""
from datetime import datetime
import functools
import time
import logging
import sys
from typing import Any, Callable, Optional
from .logging_setup import add_separator_to_log

# Global logger variable
logger = logging.getLogger('macollector')


def debug_log(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that logs the function call and return value."""
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
    """Decorator that measures the runtime of a function."""
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
        listener = None,
        log_file_path: str = '.\\logs\\config.json',
        script_start_timer: Optional[float] = None,
) -> None:
    """
    Safely exits the script and logs the finishing time and script
        execution completion.

    Args:
        log_file_path (str):
        script_start_timer (Optional[float]): The start time of the
                                                script in seconds.
        device_counter (int): The number of devices processed.

    Returns:
        None
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
