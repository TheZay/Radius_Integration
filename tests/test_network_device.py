#!/usr/bin/env python
"""
This module contains unit tests for the `network_device` module.

The `TestNetworkDevice` class tests the following:

    - The `test_connect_success` method tests the scenario where a
        connection to the network device is successful.
    - The `test_disconnect_success` method tests the scenario where a
        disconnection from the network device is successful.
    - The `test_execute_command_success` method tests the scenario where
        a command is successfully executed on the network device.
"""
import unittest
from unittest.mock import MagicMock, patch
from src.network_device import NetworkDevice

class TestNetworkDevice(unittest.TestCase):
    """
    TestNetworkDevice is a test suite for testing the NetworkDevice
    class.

    This suite includes unit tests that cover the functionality of the
    NetworkDevice class, ensuring that it correctly handles network
    connections, disconnections, and command execution.

    Attributes:
        credentials (dict): Authentication credentials used to
            instantiate NetworkDevice objects.
        device_ip (str): The IP address of the network device.
        network_device (NetworkDevice): The NetworkDevice instance under
            test.
    """
    def setUp(self):
        """
        Set up the test environment before each test case.

        This method initializes the IP address, credentials, and network
        device object for testing.
        """
        self.ip_address = '192.168.1.1'
        self.credentials = {'username': 'admin', 'password': 'password'}
        self.device = NetworkDevice(self.ip_address, self.credentials)

    def test_connect_success(self):
        """
        Test case for successful connection to a network device.

        This test case verifies that the `connect` method of the
        `NetworkDevice` class successfully establishes a connection to a
        network device using the provided IP address, credentials, and
        device type. It also checks that the hostname of the connected
        device is correctly set.
        """
        with patch('src.network_device.ConnectHandler') as mock_connect_handler:
            mock_connection = MagicMock()
            mock_connect_handler.return_value = mock_connection
            mock_connection.find_prompt.return_value = 'Switch'

            self.device.connect()

            mock_connect_handler.assert_called_once_with(
                ip=self.ip_address,
                username=self.credentials['username'],
                password=self.credentials['password'],
                device_type='cisco_ios'
            )
            self.assertEqual(self.device.hostname, 'Switch')

    def test_disconnect_success(self):
        """
        Test case to verify successful disconnection of the network
        device.

        It mocks the ConnectHandler class and asserts that the
        disconnect method is called once on the mock connection object.
        """
        with patch('src.network_device.ConnectHandler') as mock_connect_handler:
            mock_connection = MagicMock()
            mock_connect_handler.return_value = mock_connection

            self.device.connect()
            self.device.disconnect()

            mock_connection.disconnect.assert_called_once()

    def test_execute_command_success(self):
        """
        Test case to verify the success of the execute_command method.

        It mocks the ConnectHandler class and its return value to
        simulate a successful connection. The mock connection is then
        used to execute a command and the output is asserted.
        """
        with patch('src.network_device.ConnectHandler') as mock_connect_handler:
            mock_connection = MagicMock()
            mock_connect_handler.return_value = mock_connection
            mock_connection.send_command.return_value = 'command output'

            self.device.connect()
            output = self.device.execute_command('show version')

            mock_connection.send_command.assert_called_once_with(
                'show version', use_textfsm=True)
            self.assertEqual(output, [{'output': 'command output'}])

if __name__ == '__main__':
    unittest.main()
