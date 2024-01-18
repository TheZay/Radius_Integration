#!/usr/bin/env python
"""Houses the NetworkDataProcessor class for processing network data."""
import logging
import re
from typing import Callable
from .utilities import debug_log, runtime_monitor

# Global logger variable
logger = logging.getLogger('macollector')


class NetworkDataProcessor:
    """A class that processes network data and extracts VLAN and MAC
        address information."""

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_vlans(vlan_data: list[dict]):
        """
        Initiates the extraction of VLANs

        Args:
            vlan_data (list[dict]): A list of dictionaries containing
                                    VLAN information.

        Returns:
            None
        """

        logger.debug("VLAN extraction in progress")
        voip_vlans = NetworkDataProcessor.extract_voip_vlans(vlan_data)
        ap_vlans = NetworkDataProcessor.extract_ap_vlans(vlan_data)
        logger.debug("VLAN extraction completed.")
        return voip_vlans + ap_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_voip_vlans(vlan_data: list[dict]):
        """
        Extracts the VLAN IDs of VoIP VLANs from the given VLAN data.

        Args:
            vlan_data (list[dict]): A list of dictionaries containing
                                    VLAN information.

        Returns:
            None

        """
        voip_vlans = []
        for vlan_info in vlan_data:
            if (
                    'vlan_name' in vlan_info and
                    re.search(r'(?i)voip|voice\s*',
                              vlan_info['vlan_name']) and
                    vlan_info['interfaces'] and
                    NetworkDataProcessor.is_valid_vlan_id(vlan_info['vlan_id'])
            ):
                voip_vlans.append(int(vlan_info['vlan_id']))

        logger.debug("Discovered VoIP VLANs: %s", voip_vlans)
        return voip_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_ap_vlans(vlan_data: list[dict]):
        """
        Extracts the VLAN IDs of AP VLANs from the given VLAN data.

        Args:
            vlan_data (list[dict]): A list of dictionaries containing
                                    VLAN information.

        Returns:
            None

        """
        ap_vlans = []
        for vlan_info in vlan_data:
            if (
                    'vlan_name' in vlan_info and
                    re.search(r'(?i)ap|access\s*',
                              vlan_info['vlan_name']) and
                    vlan_info['interfaces'] and
                    NetworkDataProcessor.is_valid_vlan_id(vlan_info['vlan_id'])
            ):
                ap_vlans.append(int(vlan_info['vlan_id']))

        logger.debug("Discovered AP VLANs: %s", ap_vlans)
        return ap_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def collect_mac_addresses(vlan_ids: list[int],
                              command_executor: Callable) -> set[str]:
        """
        Collects MAC addresses from the switch for the specified
        VLANs.

        Returns:
            set: A set of extracted MAC addresses.
        """
        extracted_macs = set()
        for vlan_id in vlan_ids:
            command = f'show mac address-table vlan {vlan_id}'
            mac_address_table = command_executor(command)
            extracted_macs.update(
                NetworkDataProcessor.extract_mac_addresses(mac_address_table))
        return extracted_macs

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_mac_addresses(mac_address_table: list[dict]) -> set[str]:
        """
        Extracts valid MAC addresses from a given MAC address table.

        Args:
            mac_address_table (list[dict]): A list of dictionaries
                                            representing the MAC address
                                            table.
                Each dictionary should have 'destination_address' and
                    'destination_port' keys.

        Returns:
            set[str]: A set of valid MAC addresses extracted from the
                      MAC address table.
        """
        mac_addresses = set()
        po_pattern = re.compile(r'(?i)(Po|Port-Channel|Switch)')

        for mac_entry in mac_address_table:
            mac_address = mac_entry.get('destination_address')
            interfaces = mac_entry.get('destination_port')

            if not isinstance(interfaces, list):
                interfaces = [str(interfaces)]

            for interface in interfaces:
                if (interface and
                        not po_pattern.match(interface) and
                        mac_address and
                        NetworkDataProcessor.is_valid_mac_address(mac_address)):
                    logger.debug("Discovered %s on %s.",
                                 mac_address, interface)
                    mac_addresses.add(mac_address)

        return mac_addresses

    @staticmethod
    def is_valid_mac_address(mac_address: str) -> bool:
        """
        Check if a given string is a valid MAC address.

        Args:
            mac_address (str): The string to be checked.

        Returns:
            bool: True if the string is a valid MAC address, False
                  otherwise.
        """
        mac_pattern = re.compile(r"((?:[\da-fA-F]{2}[\s:.-]?){6})")
        return bool(mac_pattern.match(mac_address))

    @staticmethod
    def is_valid_vlan_id(vlan_id: str) -> bool:
        """
        Check if the given VLAN ID is valid.

        Args:
            vlan_id (str): The VLAN ID to be checked.

        Returns:
            bool: True if the VLAN ID is valid, False otherwise.
        """
        return vlan_id.isdigit() and 0 < int(vlan_id) < 4095
