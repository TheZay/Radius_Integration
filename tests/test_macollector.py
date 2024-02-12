import argparse

from src.macollector.macollector import get_credentials, main, parse_args


def test_parse_args_returns_expected_arguments(mocker):
    """
    Tests that command line arguments are correctly parsed.

    This test ensures that `parse_args` function properly parses command line arguments
    into a Namespace object with expected attributes. It mocks `argparse.ArgumentParser.parse_args`
    to return predefined arguments and compares them with expected values to verify the parsing
    functionality.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch(
        "argparse.ArgumentParser.parse_args",
        return_value=argparse.Namespace(
            file="test.txt", log_file_path="log.txt", log_level="DEBUG"
        ),
    )
    config = {"log_file_path": "log.txt", "logging_level": "DEBUG"}
    args = parse_args(config)
    assert args.file == "test.txt"
    assert args.log_file_path == "log.txt"
    assert args.log_level == "DEBUG"


def test_get_credentials_returns_expected_credentials_windows(mocker):
    """
    Tests credentials collection on Windows.

    Verifies that the `get_credentials` function correctly collects user credentials in
    a Windows environment by simulating input for username and password. The test uses
    mocking to simulate user input for both username and password fields, including simulating
    the Enter key press after the password input.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch("builtins.input", return_value="test_user")
    # Simulate "test_password" followed by enter key press
    password_input = [bytes(c, "ascii") for c in "test_password"] + [b"\r"]
    mocker.patch("msvcrt.getch", side_effect=password_input)

    logger_mock = mocker.MagicMock()
    credentials = get_credentials(logger=logger_mock)

    assert credentials == {"username": "test_user", "password": "test_password"}


def test_main_executes_expected_workflow(mocker):
    """
    Tests the main execution workflow of the macollector script.

    This test verifies that the `main` function executes its workflow as expected, including
    loading configuration, parsing arguments, setting up logging, validating input, collecting
    credentials, managing devices, exporting XML, and safely exiting. Each step in the workflow
    is mocked to prevent real execution and to assert that each function is called as expected.

    The test checks the orchestration of the main function's components, ensuring that the
    macollector script integrates its parts correctly and executes the intended workflow.

    :param mocker: Pytest fixture for mocking.
    """
    mock_load_config = mocker.patch(
        "src.macollector.macollector.load_config", return_value={}
    )
    mock_parse_args = mocker.patch(
        "src.macollector.macollector.parse_args",
        return_value=argparse.Namespace(
            file="test.txt", log_file_path="log.txt", log_level="DEBUG"
        ),
    )
    mock_setup_logging = mocker.patch(
        "src.macollector.macollector.setup_logging",
        return_value=(mocker.MagicMock(), mocker.MagicMock()),
    )
    mock_validate_input = mocker.patch(
        "src.macollector.macollector.validate_input", return_value=["192.168.1.1"]
    )
    mock_get_credentials = mocker.patch(
        "src.macollector.macollector.get_credentials",
        return_value={
            "username": "test_user",
            "password": "test_password",
        },
    )
    mock_DeviceManager = mocker.patch(
        "src.macollector.macollector.DeviceManager", return_value=mocker.MagicMock()
    )
    mock_export_xml = mocker.patch("src.macollector.macollector.export_xml")
    mock_safe_exit = mocker.patch("src.macollector.macollector.safe_exit")

    main()

    mock_load_config.assert_called_once()
    mock_parse_args.assert_called_once()
    mock_setup_logging.assert_called_once()
    mock_validate_input.assert_called_once()
    mock_get_credentials.assert_called_once()
    mock_DeviceManager.assert_called_once()
    mock_export_xml.assert_called_once()
    mock_safe_exit.assert_called_once()
