#!/usr/bin/env python
"""
This module contains the test cases for the NetworkDataProcessor class.

The NetworkDataProcessor class is responsible for processing the data
collected from the network devices and extracting the required
information from it.
"""
import unittest
from unittest.mock import MagicMock

from src.macollector.data_processor import NetworkDataProcessor


class TestNetworkDataProcessor(unittest.TestCase):
    """
    Test case for the NetworkDataProcessor class.
    
    This test case verifies the functionality of the
    NetworkDataProcessor class.
    """

    def test_extract_voip_vlans(self):
        """
        Test case to verify the extraction of VoIP VLANs from the given
        VLAN data.
        """
        vlan_data = [
            {'vlan_name': 'VoIP VLAN',
             'vlan_id': '10',
             'interfaces': ['GigabitEthernet1']},
            {'vlan_name': 'Data VLAN',
             'vlan_id': '20',
             'interfaces': ['GigabitEthernet2']},
            {'vlan_name': 'VoIP VLAN',
             'vlan_id': '30',
             'interfaces': ['GigabitEthernet3']},
        ]
        expected_voip_vlans = [10, 30]

        voip_vlans = NetworkDataProcessor.extract_voip_vlans(vlan_data)

        self.assertEqual(voip_vlans, expected_voip_vlans)

    def test_extract_ap_vlans(self):
        """
        Test case for the extract_ap_vlans method of
        NetworkDataProcessor class.
        """
        vlan_data = [
            {'vlan_name': 'AP VLAN',
             'vlan_id': '10',
             'interfaces': ['GigabitEthernet1']},
            {'vlan_name': 'Data VLAN',
             'vlan_id': '20',
             'interfaces': ['GigabitEthernet2']},
            {'vlan_name': 'AP VLAN',
             'vlan_id': '30',
             'interfaces': ['GigabitEthernet3']},
        ]
        expected_ap_vlans = [10, 30]

        ap_vlans = NetworkDataProcessor.extract_ap_vlans(vlan_data)

        self.assertEqual(ap_vlans, expected_ap_vlans)

    def test_collect_mac_addresses(self):
        """
        Test case for the collect_mac_addresses method of
        NetworkDataProcessor class.
        """
        vlan_ids = [10, 20, 30]
        command_executor = MagicMock()
        command_executor.return_value = [
            {'destination_address': '00:11:22:33:44:55',
             'destination_port': 'GigabitEthernet1'},
            {'destination_address': 'AA:BB:CC:DD:EE:FF',
             'destination_port': 'GigabitEthernet2'},
            {'destination_address': '11:22:33:44:55:66',
             'destination_port': 'GigabitEthernet3'},
        ]
        expected_mac_addresses = {
            '00:11:22:33:44:55',
            'AA:BB:CC:DD:EE:FF',
            '11:22:33:44:55:66'
        }

        mac_addresses = NetworkDataProcessor.collect_mac_addresses(
            vlan_ids, command_executor)

        self.assertEqual(mac_addresses, expected_mac_addresses)

    def test_extract_mac_addresses(self):
        """
        Test case to verify the extraction of MAC addresses from a given
        mac_address_table.
        """
        mac_address_table = [
            {'destination_address': '00:11:22:33:44:55',
             'destination_port': 'GigabitEthernet1'},
            {'destination_address': 'AA:BB:CC:DD:EE:FF',
             'destination_port': ['GigabitEthernet2', 'GigabitEthernet3']},
            {'destination_address': '11:22:33:44:55:66',
             'destination_port': 'GigabitEthernet4'},
        ]
        expected_mac_addresses = {
            '00:11:22:33:44:55',
            'AA:BB:CC:DD:EE:FF',
            '11:22:33:44:55:66'
        }

        mac_addresses = NetworkDataProcessor.extract_mac_addresses(mac_address_table)

        self.assertEqual(mac_addresses, expected_mac_addresses)

    def test_is_valid_mac_address(self):
        """
        Test case to check the validity of a MAC address.

        It verifies if the NetworkDataProcessor.is_valid_mac_address()
        method correctly identifies a valid MAC address and rejects an
        invalid MAC address.
        """
        valid_mac_address = '00:11:22:33:44:55'
        invalid_mac_address = '00:11:22:33:44'

        self.assertTrue(
            NetworkDataProcessor.is_valid_mac_address(valid_mac_address))
        self.assertFalse(
            NetworkDataProcessor.is_valid_mac_address(invalid_mac_address))

    def test_is_valid_vlan_id(self):
        """
        Test case to check the validity of a VLAN ID.

        This method tests the `is_valid_vlan_id` function of the
        `NetworkDataProcessor` class. It verifies that the function
        correctly identifies valid and invalid VLAN IDs.

        Test Steps:
        1. Define a valid VLAN ID as a string.
        2. Define an invalid VLAN ID as a string.
        3. Call the `is_valid_vlan_id` function with the valid VLAN ID
            and assert that it returns True.
        4. Call the `is_valid_vlan_id` function with the invalid VLAN ID
            and assert that it returns False.
        """
        valid_vlan_id = '10'
        invalid_vlan_id = 'abc'

        self.assertTrue(NetworkDataProcessor.is_valid_vlan_id(valid_vlan_id))
        self.assertFalse(NetworkDataProcessor.is_valid_vlan_id(invalid_vlan_id))


if __name__ == '__main__':
    unittest.main()
