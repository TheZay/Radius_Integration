#!/usr/bin/env python
import unittest
from src.file_processors import process_ip_range, InvalidInput

class TestFileProcessors(unittest.TestCase):
    """
    This test case verifies the functionality of the
    NetworkDataProcessor class.
    """
    def test_process_ip_range_single_ip(self):
        """
        Test case for the process_ip_range function when given a single
        IP address.
        """
        ip_range = "192.168.1.1"
        expected_result = ["192.168.1.1"]
        result = process_ip_range(ip_range)
        self.assertEqual(result, expected_result)

    def test_process_ip_range_range_format(self):
        """
        Test case for processing IP range in range format.

        This test verifies that the process_ip_range function correctly
        processes an IP range in the format "start_ip-end_ip" and
        returns a list of all IP addresses within that range.
        """
        ip_range = "192.168.1.1-192.168.1.5"
        expected_result = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5"
        ]
        result = process_ip_range(ip_range)
        self.assertEqual(result, expected_result)

    def test_process_ip_range_range_format_short(self):
        """
        Test case for the 'process_ip_range' function when given an IP
        range in the format '192.168.1.1-5'. It verifies that the
        function correctly processes the IP range and returns a list of
        all IP addresses within the range.
        """
        ip_range = "192.168.1.1-5"
        expected_result = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5"
        ]
        result = process_ip_range(ip_range)
        self.assertEqual(result, expected_result)

    def test_process_ip_range_multiple_ranges(self):
        """
        Test case for the 'process_ip_range' function with multiple IP
        ranges.

        The function should correctly process the given IP range string
        and return a list of all the IP addresses within the ranges.

        Input:
        - ip_range: A string representing multiple IP ranges separated
            by commas.

        Expected Output:
        - A list of all the IP addresses within the given ranges.

        Example:
        - ip_range = "192.168.1.1-192.168.1.3, 192.168.2.1-192.168.2.2"
        - expected_result = ["192.168.1.1", "192.168.1.2",
                            "192.168.1.3", "192.168.2.1", "192.168.2.2"]
        - result = process_ip_range(ip_range)
        - assert result == expected_result
        """
        ip_range = "192.168.1.1-192.168.1.3, 192.168.2.1-192.168.2.2"
        expected_result = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.2.1",
            "192.168.2.2"
        ]
        result = process_ip_range(ip_range)
        self.assertEqual(result, expected_result)

    def test_process_ip_range_invalid_range_format(self):
        """
        Test case to verify the behavior of process_ip_range function
        when an invalid IP range format is provided.
        """
        ip_range = "192.168.1.1-192.168.1"
        with self.assertRaises(InvalidInput):
            process_ip_range(ip_range)

    def test_process_ip_range_invalid_ip_address(self):
        """
        Test case to verify the behavior of process_ip_range function
        when an invalid IP address is provided in the IP range.
        """
        ip_range = "192.168.1.1, 192.168.1.256"
        with self.assertRaises(InvalidInput):
            process_ip_range(ip_range)

if __name__ == '__main__':
    unittest.main()
