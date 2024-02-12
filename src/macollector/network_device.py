#!/usr/bin/env python
"""
network_device.py: Interactions with network devices.

This module focuses on the interactions with network devices. It includes
the NetworkDevice class, which handles connections to devices, command
execution, and extraction of relevant network data like VLANs and MAC addresses.

The module utilizes Netmiko for SSH connections and Paramiko for SSH exceptions.
"""

import json
import logging
import os.path

from netmiko import (
    ConnectHandler,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from paramiko.ssh_exception import SSHException

# Local imports
from .data_processor import NetworkDataProcessor
from .utilities import debug_log, runtime_monitor

# Shared logger
logger = logging.getLogger("macollector")


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

    def __init__(
        self, ip_address: str, credentials: dict, device_type: str = "cisco_ios"
    ) -> None:
        """Initializes a NetworkDevice object."""
        self.valid_commands = None
        self.ip_address = ip_address
        self.credentials = credentials
        self.device_type = device_type
        self.connection = None
        self.hostname = "Unknown"
        self.load_valid_commands()

    def __str__(self) -> str:
        """Returns a string representation of the NetworkDevice object."""
        return f"{self.hostname} ({self.ip_address})"

    @debug_log
    @runtime_monitor
    def load_valid_commands(self, file_path: str = None) -> None:
        """Loads the valid commands for the device type from the commands.json file."""
        if file_path is None:
            # Determine the directory containing this script
            script_dir = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            )
            # Construct the absolute path to the configuration file
            file_path = os.path.join(script_dir, "configs", "commands.json")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as cmd_file:
                commands = json.load(cmd_file)
            self.valid_commands = commands.get(self.device_type, [])
        # return empty dictionary if a JSONDecodeError occurs
        except json.JSONDecodeError as e:
            logger.error("Error parsing configuration file %s: %s", file_path, e)
        # return empty dictionary if any other exception occurs
        except Exception as e:
            logger.error("Error loading configuration file %s: %s", file_path, e)
        finally:
            logger.debug("Loaded valid commands: %s", self.valid_commands)

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
                username=self.credentials["username"],
                password=self.credentials["password"],
                device_type=self.device_type,
            )
            self.connection.enable()
            self.hostname = self.connection.find_prompt().strip("#>")
            logger.info("Connected to %s (%s)", self.hostname, self.ip_address)
        except NetmikoTimeoutException as e:
            logger.error("Timeout when connecting to %s: %s", self.ip_address, e)
        except NetmikoAuthenticationException as e:
            logger.error(
                "Authentication failed when connecting to %s: %s", self.ip_address, e
            )
        except SSHException as e:
            logger.error(
                "Failed to retrieve the hostname for %s: %s", self.ip_address, e
            )

    @debug_log
    @runtime_monitor
    def disconnect(self) -> None:
        """Disconnects from the network device."""
        if not self.connection:
            raise Exception("Not connected to a device.")
        self.connection.disconnect()
        logger.info("Disconnected from %s (%s)", self.hostname, self.ip_address)

    @debug_log
    @runtime_monitor
    def execute_command(self, command: str, fsm: bool = True, **kwargs) -> list[dict]:
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
            logger.error("Not connected to device %s", self.ip_address)
            return [{None: None}]

        formatted_command = command.format(**kwargs)
        if (
            formatted_command not in self.valid_commands
            and command not in self.valid_commands
        ):
            logger.exception("Invalid command: %s", formatted_command)
            raise Exception(f"Invalid command: {formatted_command}")

        logger.info(
            'Executing command "%s" on %s (%s)',
            formatted_command,
            self.hostname,
            self.ip_address,
        )
        try:
            output = self.connection.send_command(formatted_command, use_textfsm=fsm)
        except Exception as e:
            logger.error("Error executing %s on %s: %s", command, self.ip_address, e)
            output = [{"Error": e}]

        if isinstance(output, dict):
            # Handle the case where the output is a dictionary
            output = [output]
        if isinstance(output, str):
            # Handle the case where the output is a string
            output = [{"output": output}]

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
        logger.info("Processing %s (%s)", self.hostname, self.ip_address)
        try:
            if not self.connection:
                self.connect()
            vlan_brief = self.execute_command("show vlan brief")
            vlan_ids = NetworkDataProcessor.extract_vlans(vlan_brief)
            mac_addresses: set = NetworkDataProcessor.collect_mac_addresses(
                vlan_ids, self.execute_command
            )
            logger.debug(
                "%s (%s) processed successfully: %s",
                self.hostname,
                self.ip_address,
                mac_addresses,
            )
        finally:
            self.disconnect()
        return mac_addresses
