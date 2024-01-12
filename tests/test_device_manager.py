#!/usr/bin/env python
"""
This module contains unit tests for the `device_manager` module.

The `TestDeviceManager` class tests the following:

    - The `test_process_all_devices` method tests the scenario where all
        devices in the device list are processed.
"""
import unittest
from unittest.mock import MagicMock, patch
from src.device_manager import DeviceManager

class TestDeviceManager(unittest.TestCase):
    """
    TestDeviceManager is a test suite for testing the DeviceManager
    class.

    This suite includes unit tests that cover the functionality of the
    DeviceManager class, ensuring that it correctly processes network
    devices, handles exceptions, and accurately maintains records of MAC
    addresses and failed devices.

    Attributes:
        credentials (dict): Authentication credentials used to
            instantiate NetworkDevice objects.
        device_list (list[str]): A list of IP addresses representing the
            network devices.
        device_manager (DeviceManager): The DeviceManager instance under
            test.
    """

    def setUp(self):
        """
        Set up the test environment before each test method.

        This method initializes the credentials and device_list used for
        testing the DeviceManager class. It also creates an instance of
        DeviceManager with these credentials and the device list.
        """
        self.credentials = {'username': 'admin', 'password': 'password'}
        self.device_list = ['192.168.1.1', '192.168.1.2']

    @patch('src.device_manager.NetworkDevice')
    def test_process_all_devices(self, mock_network_device_class):
        """
        Test the process_all_devices method of the DeviceManager class.

        This test ensures that DeviceManager correctly processes each
        device in the device list, updates the set of MAC addresses, and
        handles any exceptions by recording failed devices.

        The test uses a mock of the NetworkDevice class to simulate the
        processing of network devices. The mock is configured to return
        a set of MAC addresses for successful processing and to raise an
        exception for failed processing scenarios.

        Args:
            mock_network_device_class (MagicMock): A mock of the
                NetworkDevice class.

        Asserts:
            The number of unique MAC addresses is as expected.
            The number of failed devices is as expected.
            The mock NetworkDevice class is called the correct number of
                times.
        """
        mock_device_one = MagicMock()
        mock_device_one.ip_address = '192.168.1.1'
        mock_device_one.process_device.return_value = {'00:1A:2B:3C:4D:5E'}

        mock_device_two = MagicMock()
        mock_device_two.ip_address = '192.168.1.2'
        mock_device_two.process_device.side_effect = (
            Exception("Connection Error"))

        def side_effect(ip_address, _):
            if ip_address == '192.168.1.1':
                return mock_device_one
            if ip_address == '192.168.1.2':
                return mock_device_two

        mock_network_device_class.side_effect = side_effect

        device_manager = DeviceManager(self.credentials, self.device_list)
        device_manager.process_all_devices()

        self.assertEqual(len(device_manager.mac_addresses), 1)
        self.assertEqual(len(device_manager.failed_devices), 1)
        self.assertEqual(mock_network_device_class.call_count,
                         len(self.device_list))

if __name__ == '__main__':
    unittest.main()
