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
import pytest

from src.macollector.config_manager import load_config


# Test case for loading configuration from an existing file
def test_load_config_existing_file():
    """
    Test the load_config function with an existing file.

    This test case checks if the load_config function correctly loads
    the configuration from an existing file.
    """
    file_path = 'tests\\config_manager_test_dir\\expected_config.json'
    expected_config = {
        "log_file_path": "logs\\macollector.log",
        "logging_level": "DEBUG",
        "max_threads": 3,
        "retry_attempts": 1,
        "retry_delay": 2
    }
    config = load_config(file_path)
    assert config == expected_config


# Test case for loading configuration from a non-existing file
def test_load_config_non_existing_file():
    """
    Test the load_config function with a non-existing file.

    This test case checks if the load_config function correctly raises
    a FileNotFoundError when trying to load a non-existing file.
    """
    with pytest.raises(FileNotFoundError):
        load_config('non_existing_config.json')


# Test case for loading configuration from the default file path
def test_load_config_default_file_path():
    """
    Test the load_config function with the default file path.

    This test case checks if the load_config function correctly loads
    the configuration from the default file path when no file path is
    provided.
    """
    expected_config = {
        "log_file_path": "logs\\macollector.log",
        "logging_level": "INFO",
        "max_threads": 5,
        "retry_attempts": 3,
        "retry_delay": 5
    }
    config = load_config()
    assert config == expected_config


# Test case for loading configuration from a file with invalid JSON
def test_load_config_invalid_json():
    """
    Test the load_config function with a file containing invalid JSON.

    This test case checks if the load_config function correctly returns
    an empty dictionary when trying to load a file with invalid JSON.
    """
    file_path = 'tests\\config_manager_test_dir\\invalid_config.json'
    expected_config = {}
    config = load_config(file_path)
    assert config == expected_config


# Test case for loading configuration from an empty file
def test_load_config_empty_file():
    """
    Test the load_config function with an empty file.

    This test case checks if the load_config function correctly returns
    an empty dictionary when trying to load an empty file.
    """
    file_path = 'tests\\config_manager_test_dir\\empty_config.json'
    expected_config = {}
    config = load_config(file_path)
    assert config == expected_config
