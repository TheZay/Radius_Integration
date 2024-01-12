#!/usr/bin/env python
import unittest
from unittest.mock import patch, mock_open
from src.exporters import export_xml, export_txt

class TestExportFunctions(unittest.TestCase):
    """Test cases for the export functions."""

    @patch('src.exporters.input', create=True)
    @patch('src.exporters.save_formatted_xml')
    @patch('src.exporters.LOGGER')
    def test_export_xml(self, mock_logger, mock_save_xml, mock_input):
        """
        Test the export_xml function.

        This test case verifies the behavior of the export_xml function.
        It mocks the input function to provide test values for static
        host list name and description. The function is expected to call
        the save_formatted_xml function, log a debug message, and prompt
        the user for static host list name and description.
        """
        test_mac_set = {'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'}
        mock_input.side_effect = ['TestHostList', 'Test Description']

        export_xml(test_mac_set)

        mock_save_xml.assert_called_once()
        mock_logger.debug.assert_any_call('Generated XML structure')
        mock_input.assert_has_calls([
            unittest.mock.call('Specify static host list name: '),
            unittest.mock.call('Specify static host list description: ')
        ])

    @patch('builtins.open', new_callable=mock_open)
    @patch('src.exporters.os.path')
    def test_export_txt(self, mock_path, mock_file):
        """
        Test the export_txt function.

        This test case verifies the behavior of the export_txt function.
        It checks if the function correctly opens a file, writes the
        content, and verifies the written content matches the expected
        content.

        Args:
            self: The test case object.
            mock_path: The mock object for os.path module.
            mock_file: The mock object for the built-in open function.

        Returns:
            None
        """
        test_mac_set = {'AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'}
        input_file_name = 'input_file.txt'
        expected_output_file = 'input_file.txt'

        # Mocking the os.path methods
        mock_path.basename.return_value = 'input_file.txt'
        mock_path.splitext.return_value = ('input_file', '.txt')

        # Call the function
        export_txt(test_mac_set, input_file_name)

        # Check if the file is opened correctly
        mock_file.assert_called_with(f'.\\{expected_output_file}',
                                     'w', encoding="utf-8")

        # Verify the content written to the file
        written_content = ''.join(
            args[0] for args, kwargs in mock_file().write.call_args_list
        )
        expected_content = '\n'.join(test_mac_set) + '\n'
        self.assertEqual(written_content, expected_content)

if __name__ == '__main__':
    unittest.main()
