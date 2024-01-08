import unittest
from unittest.mock import patch, MagicMock
from switch_mac_collector import DeviceManager, NetworkDevice


class TestNetworkDevice(unittest.TestCase):
    def setUp(self):
        self.credentials = {'username': 'admin', 'password': 'password'}
        self.device_ip = '192.168.1.1'
        self.network_device = NetworkDevice(self.device_ip, self.credentials)

        patcher = patch('switch_mac_collector.ConnectHandler', autospec=True)
        self.mock_connect_handler = patcher.start()
        self.mock_connection = MagicMock()
        self.mock_connect_handler.return_value = self.mock_connection
        self.mock_connection.find_prompt.return_value = 'Switch>'

        # Ensure that the patcher is stopped after tests
        self.addCleanup(patcher.stop)

    def test_connect_success(self):
        # Mock the ConnectHandler used in the network device
        self.network_device.connect()

        # Assertions to check if ConnectHandler was called correctly
        self.mock_connect_handler.assert_called_once_with(
            ip=self.device_ip,
            username=self.credentials['username'],
            password=self.credentials['password'],
            device_type='cisco_ios'
        )
        self.assertEqual(self.network_device.hostname, 'Switch')

    def test_disconnect_success(self):
        self.network_device.connect()
        self.network_device.disconnect()
        # Assert that the disconnect method was called on the connection
        #  object
        self.mock_connection.disconnect.assert_called_once()

    def test_execute_command_success(self):
        self.mock_connection.send_command.return_value = 'command output'
        self.network_device.connect()
        output = self.network_device.execute_command('show version')
        self.assertEqual(output, [{'output': 'command output'}])


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

    @patch('switch_mac_collector.NetworkDevice')
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
        # Create a mock NetworkDevice instance
        mock_device_one = MagicMock()
        mock_device_one.ip_address = '192.168.1.1'
        mock_device_one.process_device.return_value = {'00:1A:2B:3C:4D:5E'}

        mock_device_two = MagicMock()
        mock_device_two.ip_address = '192.168.1.2'
        mock_device_two.process_device.side_effect = (
            Exception("Connection Error"))

        # Configuring the side effect of the NetworkDevice class constructor
        def side_effect(ip_address, credentials):
            if ip_address == '192.168.1.1':
                return mock_device_one
            elif ip_address == '192.168.1.2':
                return mock_device_two

        mock_network_device_class.side_effect = side_effect

        # Instantiate DeviceManager and process devices
        device_manager = DeviceManager(self.credentials, self.device_list)
        device_manager.process_all_devices()

        # Assertions
        self.assertEqual(len(device_manager.mac_addresses), 1)
        self.assertEqual(len(device_manager.failed_devices), 1)
        # Assert that the mock was called for each device
        self.assertEqual(mock_network_device_class.call_count,
                         len(self.device_list))


def create_mock_network_device(ip_address):
    """
    Factory method to create a mock NetworkDevice with a specified IP
    address.

    Args:
        ip_address: The IP address of the mock NetworkDevice.

    Returns:
        A mock NetworkDevice instance.
    """
    mock_device = MagicMock(spec=NetworkDevice)
    mock_device.ip_address = ip_address
    # Set up other attributes and return values as needed
    mock_device.process_device.return_value = {'00:1A:2B:3C:4D:5E'}
    return mock_device


if __name__ == '__main__':
    unittest.main()
