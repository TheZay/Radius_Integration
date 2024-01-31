#!/usr/bin/env python
import time
import unittest
from unittest.mock import MagicMock, patch

from src.macollector.utilities import debug_log, runtime_monitor, safe_exit


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""

    @patch('src.macollector.utilities.logger')
    def test_debug_log_decorator(self, mock_logger):
        """Test the debug_log decorator."""

        @debug_log
        def dummy_function(x, y):
            return x + y

        # pylint: disable=unused-variable
        result = dummy_function(5, 3)

        # Ensure that LOGGER.debug was called twice
        self.assertEqual(mock_logger.debug.call_count, 2)

        # Manually format the arguments of the first call to LOGGER.debug
        first_call_args = mock_logger.debug.call_args_list[0]
        first_call_message = first_call_args[0][0] % first_call_args[0][1:]

        # Manually format the arguments of the second call to LOGGER.debug
        second_call_args = mock_logger.debug.call_args_list[1]
        second_call_message = second_call_args[0][0] % second_call_args[0][1:]

        # Assertions
        self.assertIn('Calling dummy_function', first_call_message)
        self.assertIn('5, 3', first_call_message)
        self.assertIn('dummy_function() returned', second_call_message)
        self.assertIn('8', second_call_message)

    @patch('src.macollector.utilities.logger')
    def test_runtime_monitor_decorator(self, mock_logger):
        """Test the runtime_monitor decorator."""

        @runtime_monitor
        def dummy_function(duration):
            time.sleep(duration)
            return duration

        # pylint: disable=unused-variable
        result = dummy_function(1)

        # Check that LOGGER.debug was called
        self.assertTrue(mock_logger.debug.called)

        # Extract the actual call arguments
        call_args = mock_logger.debug.call_args_list[0]
        call_format_str, function_name, elapsed_time = call_args[0]

        # Assertions
        self.assertEqual(function_name, 'dummy_function')
        self.assertAlmostEqual(elapsed_time, 1.0, places=2)
        self.assertIn('%s() executed in %0.2f seconds.', call_format_str)

    @patch('src.macollector.utilities.logger')
    def test_safe_exit_function(self, mock_logger):
        """Test the safe_exit function."""
        with patch('sys.exit', MagicMock()) as mock_exit:
            start_time = time.perf_counter()
            safe_exit(script_start_timer=start_time,
                      device_counter=5,
                      log_file_path='test_log.log')

            # Check that LOGGER.info was called at least once
            self.assertTrue(mock_logger.info.called)

            # Extract the actual call arguments
            call_args = mock_logger.info.call_args_list[0]
            call_format_str, elapsed_time, device_count = call_args[0]

            # Assertions
            self.assertIn('The script required %0.2f seconds to finish '
                          'processing on', call_format_str)
            self.assertGreater(elapsed_time, 0.0)
            self.assertEqual(device_count, 5)
            mock_exit.assert_called_once()


if __name__ == '__main__':
    unittest.main()
