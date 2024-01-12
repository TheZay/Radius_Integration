#!/usr/bin/env python
import unittest
from unittest.mock import patch
import argparse
from src.main import parse_args, get_credentials, main

class TestSwitchMacCollector(unittest.TestCase):
    """Test cases for the Switch MAC Collector script."""

    def test_parse_args(self):
        """Test the parse_args function for correct argument parsing."""
        test_config = {
            'log_file_path': 'test_log.log',
            'logging_level': 'INFO'
        }

        test_args = [
            '-i', '192.168.1.1',
            '--log-file-path', 'test_log.log',
            '--log-level', 'DEBUG'
        ]

        # Mocking argparse.ArgumentParser.parse_args to return test args
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_parse_args.return_value = argparse.Namespace(
                ip='192.168.1.1',
                log_file_path='test_log.log',
                log_level='DEBUG'
            )

            parsed_args = parse_args(test_config)

            self.assertEqual(parsed_args.ip, '192.168.1.1')
            self.assertEqual(parsed_args.log_file_path, 'test_log.log')
            self.assertEqual(parsed_args.log_level, 'DEBUG')

    @patch('src.main.input', create=True)
    @patch('src.main.msvcrt.getch', create=True)
    @patch('src.main.LOGGER')
    def test_get_credentials(self, mock_logger, mock_getch, mock_input):
        """
        Test case for the get_credentials function.

        This test case mocks user input for username and password and
        verifies that the get_credentials function returns the expected
        credentials dictionary.

        Mocked user input:
        - Username: "test_user"
        - Password: "test_pass"

        Expected credentials dictionary:
        {
            "username": "test_user",
            "password": "test_pass"
        }
        """
        # Mocking user input for username and password
        mock_input.return_value = "test_user"
        mock_getch.side_effect = [
            b't', b'e', b's', b't', b'_', b'p', b'a', b's', b's', b'\r'
        ]

        credentials = get_credentials()

        self.assertEqual(credentials["username"], "test_user")
        self.assertEqual(credentials["password"], "test_pass")

    @patch('src.main.load_config')
    @patch('src.main.parse_args')
    @patch('src.main.setup_logging')
    @patch('src.main.validate_input')
    @patch('src.main.get_credentials')
    @patch('src.main.DeviceManager')
    @patch('src.main.export_xml')
    @patch('src.main.safe_exit')
    @patch('src.main.LOGGER')
    def test_main(self, mock_logger, mock_safe_exit, mock_export_xml,
                  mock_device_manager, mock_get_credentials,
                  mock_validate_input, mock_setup_logging,
                  mock_parse_args, mock_load_config):
        """
        Test case for the main function.

        Args:
            mock_logger: Mock object for the logger.
            mock_safe_exit: Mock object for the safe_exit function.
            mock_export_xml: Mock object for the export_xml function.
            mock_device_manager: Mock object for the device_manager function.
            mock_get_credentials: Mock object for the get_credentials function.
            mock_validate_input: Mock object for the validate_input function.
            mock_setup_logging: Mock object for the setup_logging function.
            mock_parse_args: Mock object for the parse_args function.
            mock_load_config: Mock object for the load_config function.
        """
        mock_load_config.return_value = {"log_file_path": "test_log.log",
                                         "logging_level": "INFO"}
        mock_parse_args.return_value = argparse.Namespace(
            ip='192.168.1.1',
            log_file_path='test_log.log',
            log_level='DEBUG'
        )
        mock_get_credentials.return_value = {"username": "user",
                                             "password": "pass"}
        mock_validate_input.return_value = ['192.168.1.1']

        main()

        # Assertions to verify the workflow
        mock_load_config.assert_called_once()
        mock_parse_args.assert_called_once()
        mock_setup_logging.assert_called_once()
        mock_validate_input.assert_called_once()
        mock_get_credentials.assert_called_once()
        mock_device_manager.assert_called_once()
        mock_export_xml.assert_called_once()
        mock_safe_exit.assert_called_once()



if __name__ == '__main__':
    unittest.main()
