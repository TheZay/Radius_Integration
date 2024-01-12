#!/usr/bin/env python
"""
This module contains unit tests for the `config_manager` module.

The `TestLoadConfig` class tests the following:

    - The `test_load_config_existing_file` method tests the scenario
        where the configuration is loaded from an existing file.
    - The `test_load_config_non_existing_file` method tests the scenario
        where a `FileNotFoundError` is raised when trying to load a
        non-existing config file.
    - The `test_load_config_default_file_path` method tests the scenario
        where the default configuration file path is used.
"""
import unittest
from src.config_manager import load_config

class TestLoadConfig(unittest.TestCase):
    """
    Test case class for testing the load_config function.

    This class contains test cases that verify the behavior of the
    load_config function when given an existing file path and when given
    a non-existing file path.
    """
    def test_load_config_existing_file(self):
        """
        Test case to verify the behavior of the load_config function
        when loading an existing file.

        The function should load the configuration from the specified
        file path and return the expected configuration.

        Steps:
        1. Arrange the necessary test data, including the file path and
            the expected configuration.
        2. Call the load_config function with the file path.
        3. Assert that the returned configuration matches the expected
            configuration.
        """
        # Arrange
        file_path = 'tests\\config_manager_test_dir\\config.json'
        expected_config = {
            "log_file_path": "logs\\switch_collector.log",
            "logging_level": "DEBUG",
            "max_threads": 3,
            "retry_attempts": 1,
            "retry_delay": 2
        }

        # Act
        config = load_config(file_path)

        # Assert
        self.assertEqual(config, expected_config)

    def test_load_config_non_existing_file(self):
        """
        Test case to verify the behavior of load_config function when
        given a non-existing file path.

        It should raise a FileNotFoundError.
        """
        # Arrange
        file_path = 'non_existing_config.json'

        # Act and Assert
        with self.assertRaises(FileNotFoundError):
            load_config(file_path)

    def test_load_config_default_file_path(self):
        """
        Test case to verify the behavior of the load_config function
        when using the default file path.

        The expected behavior is that the function should return an
        empty dictionary as the default configuration.

        """
        # Arrange
        expected_config = {
            "log_file_path": "logs\\switch_mac_collector.log",
            "logging_level": "INFO",
            "max_threads": 5,
            "retry_attempts": 3,
            "retry_delay": 5
        }

        # Act
        config = load_config()

        # Assert
        self.assertEqual(config, expected_config)

if __name__ == '__main__':
    unittest.main()
