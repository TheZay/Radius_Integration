#!/usr/bin/env python
import logging
import os
import time
import unittest

from src.macollector.logging_setup import add_separator_to_log, setup_logging


class TestLoggingSetup(unittest.TestCase):
    """Test cases for logging setup."""

    def setUp(self):
        """Set up test fixtures."""
        self.logger = logging.getLogger('test_macollector')
        self.test_log_file = 'test_log.log'
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)

    def tearDown(self):
        """Tear down test fixtures."""
        # Close all handlers associated with the logger
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)

        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)

    def test_setup_logging(self):
        """Test the setup_logging function."""
        setup_logging(self.test_log_file, 'INFO')

        # Check if the log file is created
        self.assertTrue(os.path.exists(self.test_log_file))

        # Creating a test log entry
        self.logger.info("Test log entry")

        # Allow some time for the log entry to be written
        time.sleep(1)

        # Check if the log entry is written to the file
        with open(self.test_log_file, 'r', encoding="utf-8") as file:
            content = file.read()
            self.assertIn("Test log entry", content)

    def test_add_separator_to_log(self):
        """Test the add_separator_to_log function."""
        separator = '-' * 80
        add_separator_to_log(self.test_log_file, separator)

        # Check if the separator is appended to the file
        with open(self.test_log_file, 'r', encoding="utf-8") as file:
            content = file.read()
            self.assertTrue(content.endswith(separator + '\n'))


if __name__ == '__main__':
    unittest.main()
