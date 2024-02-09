#!/usr/bin/env python
"""
data_processor.py: Processes network data.

This module contains the NetworkDataProcessor class, responsible for
extracting VLAN and MAC address information from network data. It utilizes
regular expressions and standard Python data structures.

The class methods focus on extracting different types of VLAN IDs and
MAC addresses from provided network data. Exception handling is internal,
and only results are returned.
"""

import logging
import re
from typing import Callable, List, Set

# Local imports
from .utilities import debug_log, runtime_monitor

# Shared logger
logger = logging.getLogger("macollector")


class NetworkDataProcessor:
    """
    Processes network data, extracting VLAN and MAC address information.

    This class provides static methods to extract VLAN IDs (both VoIP and AP)
    and MAC addresses from provided network data. Methods use regex for
    data identification and filtering.
    """

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_vlans(vlan_data: List[dict]) -> List[int]:
        """
        Extracts VLAN IDs from the given VLAN data.

        :param vlan_data: A list of dictionaries containing VLAN info.
        :type vlan_data: List[dict]
        :return: List of extracted VLAN IDs.
        :rtype: List[int]
        """
        logger.debug("VLAN extraction in progress")
        voip_vlans = NetworkDataProcessor.extract_voip_vlans(vlan_data)
        ap_vlans = NetworkDataProcessor.extract_ap_vlans(vlan_data)
        logger.debug("VLAN extraction completed.")
        return voip_vlans + ap_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_voip_vlans(vlan_data: List[dict]) -> List[int]:
        """
        Extracts VoIP VLAN IDs from the provided VLAN data.

        :param vlan_data: List of dictionaries with VLAN information.
        :type vlan_data: List[dict]
        :return: List of extracted VoIP VLAN IDs.
        :rtype: List[int]
        """
        voip_vlans = []
        for vlan_info in vlan_data:
            if NetworkDataProcessor.is_voip_vlan(vlan_info):
                voip_vlans.append(int(vlan_info["vlan_id"]))
        logger.debug("Discovered VoIP VLANs: %s", voip_vlans)
        return voip_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_ap_vlans(vlan_data: List[dict]) -> List[int]:
        """
        Extracts AP VLAN IDs from the provided VLAN data.

        :param vlan_data: List of dictionaries with VLAN information.
        :type vlan_data: List[dict]
        :return: List of extracted AP VLAN IDs.
        :rtype: List[int]
        """
        ap_vlans = []
        for vlan_info in vlan_data:
            if NetworkDataProcessor.is_ap_vlan(vlan_info):
                ap_vlans.append(int(vlan_info["vlan_id"]))
        logger.debug("Discovered AP VLANs: %s", ap_vlans)
        return ap_vlans

    @staticmethod
    @debug_log
    @runtime_monitor
    def collect_mac_addresses(
        vlan_ids: List[int], command_executor: Callable
    ) -> Set[str]:
        """
        Collects MAC addresses from specified VLANs.

        :param vlan_ids: List of VLAN IDs to collect MAC addresses from.
        :type vlan_ids: List[int]
        :param command_executor: Function to execute network commands.
        :type command_executor: Callable
        :return: Set of MAC addresses extracted from the VLANs.
        :rtype: Set[str]
        """
        extracted_macs = set()
        for vlan_id in vlan_ids:
            command = "show mac address-table vlan {vlan_id}"
            mac_address_table = command_executor(command, vlan_id=vlan_id)
            extracted_macs.update(
                NetworkDataProcessor.extract_mac_addresses(mac_address_table)
            )
        return extracted_macs

    @staticmethod
    @debug_log
    @runtime_monitor
    def extract_mac_addresses(mac_address_table: List[dict]) -> Set[str]:
        """
        Extracts valid MAC addresses from a given MAC address table.

        :param mac_address_table: List of dictionaries representing the
                                    MAC address table.
        :type mac_address_table: List[dict]
        :return: Set of valid MAC addresses extracted from the table.
        :rtype: Set[str]
        """
        mac_addresses = set()
        po_pattern = re.compile(r"(?i)(Po|Port-Channel|Switch)")

        for mac_entry in mac_address_table:
            mac_address = mac_entry.get("destination_address")
            interfaces = mac_entry.get("destination_port")

            if not isinstance(interfaces, list):
                interfaces = [str(interfaces)]

            mac_addresses.update(
                NetworkDataProcessor.valid_mac_addresses(
                    mac_address, interfaces, po_pattern
                )
            )
        return mac_addresses

    @staticmethod
    def valid_mac_addresses(
        mac_address: str, interfaces: List[str], pattern: re.Pattern
    ) -> Set[str]:
        """
        Filters valid MAC addresses based on interface and pattern.

        :param mac_address: MAC address to be checked.
        :type mac_address: str
        :param interfaces: List of interfaces.
        :type interfaces: List[str]
        :param pattern: Compiled regex pattern to match interfaces.
        :type pattern: re.Pattern
        :return: Set of valid MAC addresses.
        :rtype: Set[str]
        """
        return {
            mac_address
            for interface in interfaces
            if interface
            and not pattern.match(interface)
            and NetworkDataProcessor.is_valid_mac_address(mac_address)
        }

    @staticmethod
    def is_voip_vlan(vlan_info: dict) -> bool:
        """
        Determines if a VLAN is a VoIP VLAN.

        :param vlan_info: VLAN information.
        :type vlan_info: dict
        :return: True if it's a VoIP VLAN, False otherwise.
        :rtype: bool
        """
        return (
            "vlan_name" in vlan_info
            and re.search(r"(?i)voip|voice\s*", vlan_info["vlan_name"])
            and vlan_info["interfaces"]
            and NetworkDataProcessor.is_valid_vlan_id(vlan_info["vlan_id"])
        )

    @staticmethod
    def is_ap_vlan(vlan_info: dict) -> bool:
        """
        Determines if a VLAN is an AP VLAN.

        :param vlan_info: VLAN information.
        :type vlan_info: dict
        :return: True if it's an AP VLAN, False otherwise.
        :rtype: bool
        """
        return (
            "vlan_name" in vlan_info
            and re.search(r"(?i)ap|access\s*", vlan_info["vlan_name"])
            and vlan_info["interfaces"]
            and NetworkDataProcessor.is_valid_vlan_id(vlan_info["vlan_id"])
        )

    @staticmethod
    def is_valid_mac_address(mac_address: str) -> bool:
        """
        Checks if a string is a valid MAC address.

        :param mac_address: MAC address to validate.
        :type mac_address: str
        :return: True if valid, False otherwise.
        :rtype: bool
        """
        mac_pattern = re.compile(r"((?:[\da-fA-F]{2}[\s:.-]?){6})")
        return bool(mac_pattern.match(mac_address))

    @staticmethod
    def is_valid_vlan_id(vlan_id: str) -> bool:
        """
        Checks if a VLAN ID is valid.

        :param vlan_id: VLAN ID to validate.
        :type vlan_id: str
        :return: True if valid, False otherwise.
        :rtype: bool
        """
        return vlan_id.isdigit() and 0 < int(vlan_id) < 4095
