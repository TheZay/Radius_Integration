import unittest
from unittest.mock import patch, MagicMock
from switch_mac_collector import DeviceManager, NetworkDevice


class TestNetworkDevice(unittest.TestCase):
    def setUp(self):
        self.credentials = {'username': 'admin', 'password': 'password'}
        self.device_ip = '192.168.1.1'
        self.network_device = NetworkDevice(self.device_ip, self.credentials)

    @patch('switch_mac_collector.ConnectHandler')
    def test_connect(self, mock_connect_handler):
        # Set up the mock to behave as expected
        mock_connect_handler.return_value = MagicMock()
        mock_connect_handler.return_value.find_prompt.return_value = 'Switch>'

        # Mock the ConnectHandler used in the network device
        self.network_device.connect()

        # Assertions to check if ConnectHandler was called correctly
        mock_connect_handler.assert_called_once_with(
            ip=self.device_ip,
            username=self.credentials['username'],
            password=self.credentials['password'],
            device_type='cisco_ios'
        )
        self.assertEqual(self.network_device.hostname, 'Switch')


class TestDeviceManager(unittest.TestCase):
    def setUp(self):
        self.credentials = {'username': 'admin', 'password': 'password'}
        self.device_list = ['192.168.1.1', '192.168.1.2']

    @patch('switch_mac_collector.NetworkDevice')
    def test_process_all_devices(self, mock_network_device_class):
        # Create a mock NetworkDevice instance
        mock_network_device_instance = MagicMock()
        # Set the return value for the process_device method
        mock_network_device_instance.process_device.return_value = {
            '00:1A:2B:3C:4D:5E',
            '20:15:fc:a1:35:88'
        }
        # Set the return value for the NetworkDevice class constructor
        mock_network_device_class.return_value = mock_network_device_instance

        device_manager = DeviceManager(self.credentials, self.device_list)
        device_manager.process_all_devices()

        # Assertions
        self.assertEqual(len(device_manager.mac_addresses), 2)
        self.assertEqual(len(device_manager.failed_devices), 0)
        # Assert that the mock was called for each device
        self.assertEqual(mock_network_device_class.call_count,
                         len(self.device_list))


if __name__ == '__main__':
    unittest.main()
