"""This module contains custom exception classes for the script."""
class ScriptExit(Exception):
    """
    Custom exception class for script termination.

    Attributes:
        message (str): The error message associated with the exception.
        exit_code (int): The exit code to be returned when the script
                            terminates.
    """

    def __init__(self, message, exit_code=1):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


class InvalidInput(Exception):
    """
    Exception raised for invalid input.

    Attributes:
        message (str): Explanation of the error
        exit_code (int): Exit code associated with the error
    """

    def __init__(self, message, exit_code=2):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'
