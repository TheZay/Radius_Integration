"""Focuses on direct interactions with the network devices."""
from netmiko import (ConnectHandler, NetmikoAuthenticationException,
                     NetmikoTimeoutException)
from paramiko.ssh_exception import SSHException

from .data_processor import NetworkDataProcessor
from .utilities import debug_log, runtime_monitor
from .logging_setup import LOGGER


class NetworkDevice:
    """
    A class that represents a network device.

    Attributes:
        ip_address (str): The IP address of the network device.
        credentials (dict): A dictionary containing the username and
                            password for authentication.
        device_type (str): The type of the network device.
        connection (BaseConnection): The connection object for
                                     interacting with the device.
        hostname (str): The hostname of the network device.
        voip_vlans (list[int]): A list of VLAN IDs for VoIP VLANs.
        ap_vlans (list[int]): A list of VLAN IDs for AP VLANs.

    Methods:
        __init__(self, ip_address, credentials) -> None:
            Initializes a NetworkDevice object.
        connect(self) -> None: Connects to the device using the provided
                               credentials and device type.
        disconnect(self) -> None: Disconnects from the switch.
        execute_command(self, command, fsm=True) -> list[dict]:
            Executes a command on the device and returns the output.
        extract_voip_vlans(self, vlan_data) -> None:
            Extracts the VLAN IDs of VoIP VLANs from the given VLAN data.
        extract_ap_vlans(self, vlan_data) -> None:
            Extracts the VLAN IDs of AP VLANs from the given VLAN data.
        is_valid_vlan_id(self, vlan_id) -> bool:
            Check if the given VLAN ID is valid.
    """


    def __init__(self, ip_address: str, credentials: dict) -> None:
        """
        Initializes a NetworkDevice object.

        Args:
            ip_address (str): The IP address of the network device.
            credentials (dict): A dictionary containing the username and
                                password for authentication.
        """
        self.ip_address = ip_address
        self.credentials = credentials
        self.device_type = 'cisco_ios'
        self.connection = None
        self.hostname = "Unknown"

    @debug_log
    @runtime_monitor
    def connect(self) -> None:
        """
        Connects to the device using the provided credentials and device
            type.

        Raises:
            NetmikoTimeoutException: If a timeout occurs while
                                        connecting to the device.
            NetmikoAuthenticationException: If authentication fails while
                                            connecting to the device.
            SSHException: If failed to retrieve the hostname for the
                            device.

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
            LOGGER.info("Connected to %s (%s)",
                        self.hostname, self.ip_address)
        except NetmikoTimeoutException as e:
            LOGGER.error("Timeout when connecting to %s: %s",
                         self.ip_address, e)
        except NetmikoAuthenticationException as e:
            LOGGER.error("Authentication failed when connecting to %s: %s",
                         self.ip_address, e)
        except SSHException as e:
            LOGGER.error("Failed to retrieve the hostname for %s: %s",
                         self.ip_address, e)

    @debug_log
    @runtime_monitor
    def disconnect(self) -> None:
        """
        Disconnects from the switch.

        This method disconnects the current connection from the
            switch.
        """
        if self.connection:
            self.connection.disconnect()
            LOGGER.info("Disconnected from %s (%s)",
                        self.hostname, self.ip_address)

    @debug_log
    @runtime_monitor
    def execute_command(self, command: str, fsm: bool = True) -> list[dict]:
        """
        Executes a command on the device and returns the output.

        Args:
            command (str): The command to be executed on the device.
            fsm (bool, optional): Whether to use TextFSM for parsing the
                                    output. Defaults to True.

        Returns:
            list[dict]: A list of dictionaries representing the output
                        of the command.
        """
        if not self.connection:
            LOGGER.error("Not connected to device %s",
                         self.ip_address)
            return [{None: None}]

        LOGGER.info('Executing command "%s" on %s (%s)',
                    command, self.hostname, self.ip_address)
        try:
            output = self.connection.send_command(command, use_textfsm=fsm)
        except Exception as e:
            LOGGER.error("Error executing %s on %s: %s",
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
    def process_device(self):
        """
        Process the device by connecting to it, extracting VLAN
        information, collecting MAC addresses, and then disconnecting
        from the device.

        Returns:
            list: A list of MAC addresses collected from the device.
        """
        LOGGER.info("Processing %s (%s)",
                    self.hostname, self.ip_address)
        try:
            self.connect()
            vlan_brief = self.execute_command('show vlan brief')
            vlan_ids = NetworkDataProcessor.extract_vlans(vlan_brief)
            mac_addresses = NetworkDataProcessor.collect_mac_addresses(
                vlan_ids, self.execute_command)
        finally:
            self.disconnect()
        LOGGER.info("Finished processing %s (%s)",
                    self.hostname, self.ip_address)
        return mac_addresses
