import logging
from logging.handlers import RotatingFileHandler

import pytest

from src.macollector.logging_setup import add_separator_to_log, setup_logging


@pytest.fixture
def temp_log_file(tmp_path):
    """
    Creates a temporary log file for testing.

    This fixture utilizes pytest's `tmp_path` fixture to generate a temporary file path
    for a log file. It is used in tests that require writing to or reading from a log file,
    ensuring that tests do not affect the actual log files and are isolated from each other.

    :param tmp_path: Pytest fixture that provides a temporary directory unique to the test function.
    :return: A Path object pointing to the temporary log file.
    """
    return tmp_path / "test_log.log"


def test_setup_logging_initialization(temp_log_file):
    """
    Tests the initialization of the logging setup.

    Verifies that `setup_logging` correctly initializes the logging system with a DEBUG level
    logger and adds both StreamHandler and RotatingFileHandler to the logger. This test ensures
    that the logging setup is correctly configured as expected by the application.

    The test also checks that the logger and listener are successfully created and that the
    listener is properly stopped during cleanup to avoid any side effects.

    :param temp_log_file: Fixture providing a path to a temporary log file.
    """
    logger, listener = setup_logging(str(temp_log_file))

    # Check that logger is initialized correctly
    assert logger is not None
    assert logger.level == logging.DEBUG  # Default logger level set in function

    # Verify handlers are added
    handlers_types = [type(handler) for handler in logger.handlers]
    assert logging.StreamHandler in handlers_types
    assert logging.handlers.RotatingFileHandler in handlers_types

    # Cleanup by stopping the listener
    listener.stop()


def test_add_separator_to_log(temp_log_file):
    """
    Tests adding a separator line to the log file.

    Verifies that the `add_separator_to_log` function correctly writes a specified separator
    string to the end of the log file. This test ensures that log file readability is enhanced
    by the ability to insert visual separators between log entries.

    After adding a separator, the test checks the last line of the log file to confirm that
    the separator was correctly appended.

    :param temp_log_file: Fixture providing a path to a temporary log file.
    """
    separator = "===" * 10
    add_separator_to_log(str(temp_log_file), separator=separator)

    # Read the last line of the file
    with open(str(temp_log_file), "r", encoding="utf-8") as log_file:
        lines = log_file.readlines()
        last_line = lines[-1].strip()

    # Check that the last line is the separator
    assert last_line == separator
