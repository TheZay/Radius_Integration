import json
import logging

import pytest

from src.macollector.config_manager import load_config


def test_load_config_file_not_found(monkeypatch):
    """
    Test loading configuration with a non-existent file path.

    This test ensures that a FileNotFoundError is raised when attempting to load
    configuration from a file that does not exist. The test uses monkeypatch to mock
    os.path.exists to always return False, simulating the absence of the file.

    :param monkeypatch: Pytest fixture to mock functions and methods.
    """
    # Mock os.path.exists to always return False
    monkeypatch.setattr("os.path.exists", lambda path: False)

    # Verify FileNotFoundError is raised
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent_config.json")


def test_load_config_invalid_json(tmp_path, caplog):
    """
    Test loading configuration from a file containing invalid JSON.

    Verifies that loading an invalid JSON configuration file logs an appropriate error
    message and returns an empty dictionary. The test creates a temporary file with
    invalid JSON content to simulate this scenario.

    :param tmp_path: Pytest fixture to create and return a temporary directory.
    :param caplog: Pytest fixture to capture log messages.
    """
    # Create a temporary JSON file with invalid content
    invalid_json_file = tmp_path / "invalid.json"
    invalid_json_file.write_text("invalid json")

    # Capture logging
    with caplog.at_level(logging.ERROR):
        # Attempt to load the invalid JSON, expecting an empty dict
        config = load_config(str(invalid_json_file))
        assert config == {}, "Expected an empty dictionary for invalid JSON"
        assert (
            "Error parsing configuration file" in caplog.text
        ), "Expected an error log for invalid JSON"


def test_load_config_valid_json(monkeypatch, tmp_path, caplog):
    """
    Test loading configuration from a valid JSON file.

    Ensures that a valid JSON configuration file is correctly parsed into a dictionary.
    The test creates a temporary file with valid JSON content to simulate this scenario.

    :param monkeypatch: Pytest fixture to mock functions and methods.
    :param tmp_path: Pytest fixture to create and return temporary directory.
    :param caplog: Pytest fixture to capture log messages.
    """
    # Prepare a valid JSON content
    valid_config = {"key": "value"}
    valid_json_content = json.dumps(valid_config)

    # Create a temporary valid JSON file
    valid_json_file = tmp_path / "valid.json"
    valid_json_file.write_text(valid_json_content)

    # Load the configuration and verify the content
    loaded_config = load_config(str(valid_json_file))
    assert (
        loaded_config == valid_config
    ), "Expected configuration dictionary to match the JSON content"


def test_load_config_unexpected_error(monkeypatch, caplog):
    """
    Test handling of unexpected errors during configuration loading.

    Simulates an unexpected IOError during the configuration loading process to test
    error handling and logging. The test uses monkeypatch to replace the built-in open
    function with one that raises an IOError.

    :param monkeypatch: Pytest fixture to mock functions and methods.
    :param caplog: Pytest fixture to capture log messages.
    """

    # Define a function to be used as the side effect of open
    def raise_io_error(*args, **kwargs):
        raise IOError("Unexpected error")

    # Use monkeypatch to replace 'open' with a function that raises an IOError
    monkeypatch.setattr("builtins.open", raise_io_error)

    # Ensure os.path.exists returns True so that we attempt to open the file
    monkeypatch.setattr("os.path.exists", lambda path: True)

    # Set the logging level to capture with caplog
    with caplog.at_level(logging.ERROR):
        # Call the function and expect an empty dict due to the handled error
        config = load_config("any_path.json")
        assert config == {}, "Expected an empty dictionary on unexpected error"
        # Check if the appropriate error message was logged
        assert (
            "Error loading configuration file" in caplog.text
        ), "Expected an error log for unexpected error"
