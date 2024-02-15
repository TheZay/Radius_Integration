#!/usr/bin/env python
"""
exceptions.py: Custom exceptions for the script.

This module defines custom exception classes used throughout the script,
including ScriptExit for script termination and InvalidInput for handling
invalid inputs.
"""


class ScriptExit(Exception):
    """
    Custom exception for indicating script termination.

    This exception is raised to signify an intended exit from the script,
    usually due to an error or exceptional condition. It carries an exit
    code and a message explaining the reason for the termination.

    :param message: Error message associated with the script termination.
    :type message: str
    :param exit_code: Exit code to be returned upon termination, defaults to 1.
    :type exit_code: int, optional
    """

    def __init__(self, message, exit_code=1):
        """Initialize ScriptExit exception."""
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


class InvalidInput(Exception):
    """
    Exception raised for invalid input.

    This exception is used to indicate that an input to the script is invalid
    or malformed. It helps in providing a clearer context when such errors
    occur during script execution.

    :param message: Explanation of the error.
    :type message: str
    :param exit_code: Exit code associated with the error, defaults to 2.
    :type exit_code: int, optional
    """

    def __init__(self, message, exit_code=2):
        """Initialize InvalidInput exception."""
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'
