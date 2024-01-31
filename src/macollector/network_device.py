#!/usr/bin/env python
"""
network_device.py: Interactions with network devices.

This module focuses on the interactions with network devices. It includes
the NetworkDevice class, which handles connections to devices, command
execution, and extraction of relevant network data like VLANs and MAC addresses.

The module utilizes Netmiko for SSH connections and Paramiko for SSH exceptions.
"""

import logging

from netmiko import (ConnectHandler, NetmikoAuthenticationException,
                     NetmikoTimeoutException)
from paramiko.ssh_exception import SSHException

# Local imports
from .data_processor import NetworkDataProcessor
from .utilities import debug_log, runtime_monitor

# Shared logger
logger = logging.getLogger('macollector')


class NetworkDevice:
    """
    Represents and manages a single network device.

    This class encapsulates the operations for a network device, including
    connecting, disconnecting, executing commands, and processing VLAN and
    MAC address information.

    :param ip_address: IP address of the network device.
    :type ip_address: str
    :param credentials: Credentials (username, password) for device access.
    :type credentials: dict
    """

    def __init__(self, ip_address: str, credentials: dict) -> None:
        """Initializes a NetworkDevice object."""
        self.ip_address = ip_address
        self.credentials = credentials
        self.device_type = 'cisco_ios'
        self.connection = None
        self.hostname = "Unknown"

    @debug_log
    @runtime_monitor
    def connect(self) -> None:
        """
        Establishes a connection to the network device.

        Attempts to connect to the device using SSH with the provided
        credentials. If successful, retrieves the device's hostname.

        :raises NetmikoTimeoutException: If a timeout occurs during connection.
        :raises NetmikoAuthenticationException: If authentication fails.
        :raises SSHException: If hostname retrieval fails.
        """
        try:
            self.connection = ConnectHandler(
                ip=self.ip_address,
                username=self.credentials['username'],
                password=self.credentials['password'],
                device_type=self.device_type
            )
            self.connection.enable()
            self.hostname = self.connection.find_prompt().strip('#>')
            logger.info("Connected to %s (%s)",
                        self.hostname, self.ip_address)
        except NetmikoTimeoutException as e:
            logger.error("Timeout when connecting to %s: %s",
                         self.ip_address, e)
        except NetmikoAuthenticationException as e:
            logger.error("Authentication failed when connecting to %s: %s",
                         self.ip_address, e)
        except SSHException as e:
            logger.error("Failed to retrieve the hostname for %s: %s",
                         self.ip_address, e)

    @debug_log
    @runtime_monitor
    def disconnect(self) -> None:
        """Disconnects from the network device."""
        if self.connection:
            self.connection.disconnect()
            logger.info("Disconnected from %s (%s)",
                        self.hostname, self.ip_address)

    @debug_log
    @runtime_monitor
    def execute_command(self, command: str, fsm: bool = True) -> list[dict]:
        """
        Executes a command on the device and returns the output.

        Sends a command to the connected device and optionally parses the
        output using TextFSM.

        :param command: Command to be executed on the device.
        :type command: str
        :param fsm: Whether to use TextFSM for parsing the output.
        :type fsm: bool, optional
        :return: List of dictionaries representing the command output.
        :rtype: list[dict]
        """
        if not self.connection:
            logger.error("Not connected to device %s",
                         self.ip_address)
            return [{None: None}]

        logger.info('Executing command "%s" on %s (%s)',
                    command, self.hostname, self.ip_address)
        try:
            output = self.connection.send_command(command, use_textfsm=fsm)
        except Exception as e:
            logger.error("Error executing %s on %s: %s",
                         command, self.ip_address, e)
            output = [{'Error': e}]

        if isinstance(output, dict):
            # Handle the case where the output is a dictionary
            output = [output]
        if isinstance(output, str):
            # Handle the case where the output is a string
            output = [{'output': output}]

        return output

    @debug_log
    @runtime_monitor
    def process_device(self) -> set:
        """
        Processes the device to collect MAC addresses.

        Connects to the device, retrieves VLAN information, collects MAC
        addresses, and then disconnects.

        :return: List of collected MAC addresses.
        :rtype: set
        """
        logger.info("Processing %s (%s)",
                    self.hostname, self.ip_address)
        try:
            self.connect()
            vlan_brief = self.execute_command('show vlan brief')
            vlan_ids = NetworkDataProcessor.extract_vlans(vlan_brief)
            mac_addresses: set = NetworkDataProcessor.collect_mac_addresses(
                vlan_ids, self.execute_command)
        finally:
            self.disconnect()
        logger.info("Finished processing %s (%s)",
                    self.hostname, self.ip_address)
        return mac_addresses
