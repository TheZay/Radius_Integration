#!/usr/bin/env python
import unittest
from src.exceptions import ScriptExit, InvalidInput

class TestScriptExit(unittest.TestCase):
    """Test cases for the ScriptExit exception."""

    def test_script_exit_initialization(self):
        """Test the initialization of ScriptExit exception."""
        message = "Test error"
        exit_code = 1
        exception = ScriptExit(message, exit_code)

        self.assertEqual(exception.message, message)
        self.assertEqual(exception.exit_code, exit_code)

    def test_script_exit_str(self):
        """Test the string representation of ScriptExit exception."""
        message = "Test error"
        exit_code = 1
        exception = ScriptExit(message, exit_code)

        expected_str = f'{message} (exit code: {exit_code})'
        self.assertEqual(str(exception), expected_str)

class TestInvalidInput(unittest.TestCase):
    """Test cases for the InvalidInput exception."""

    def test_invalid_input_initialization(self):
        """Test the initialization of InvalidInput exception."""
        message = "Invalid input error"
        exit_code = 2
        exception = InvalidInput(message, exit_code)

        self.assertEqual(exception.message, message)
        self.assertEqual(exception.exit_code, exit_code)

    def test_invalid_input_str(self):
        """Test the string representation of InvalidInput exception."""
        message = "Invalid input error"
        exit_code = 2
        exception = InvalidInput(message, exit_code)

        expected_str = f'{message} (exit code: {exit_code})'
        self.assertEqual(str(exception), expected_str)


if __name__ == '__main__':
    unittest.main()
