import pytest

from src.macollector.exceptions import InvalidInput, ScriptExit


def test_invalid_input_exception():
    """
    Tests the InvalidInput exception for correct message and exit code attributes.

    This test verifies that when the InvalidInput exception is raised, it correctly encapsulates
    the provided message and exit code within its attributes. The test checks both the string
    representation of the exception and the exit_code attribute to ensure they match expected values.

    Ensures that the exception accurately represents errors related to invalid user input, facilitating
    debugging and error handling in the application.
    """
    message = "Invalid input provided"
    exit_code = 2

    with pytest.raises(InvalidInput) as excinfo:
        raise InvalidInput(message, exit_code=exit_code)

    assert (
        str(excinfo.value) == f"{message} (exit code: {exit_code})"
    ), "InvalidInput Exception message does not match"
    assert (
        excinfo.value.exit_code == exit_code
    ), "InvalidInput Exception exit code does not match"


def test_script_exit_exception():
    """
    Tests the ScriptExit exception for accurate message and exit code attributes.

    This test ensures that when the ScriptExit exception is raised, it properly includes the given
    message and exit code within its attributes. It evaluates the string representation of the exception
    and the exit_code attribute to confirm they align with expected values.

    Validates that the exception serves its purpose in signaling the need for the script to exit due
    to an error, with precise error reporting for logging or user notification.
    """
    message = "Script exited due to error"
    exit_code = 1

    with pytest.raises(ScriptExit) as excinfo:
        raise ScriptExit(message, exit_code=exit_code)

    assert (
        str(excinfo.value) == f"{message} (exit code: {exit_code})"
    ), "ScriptExit Exception message does not match"
    assert (
        excinfo.value.exit_code == exit_code
    ), "ScriptExit Exception exit code does not match"
