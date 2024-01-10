"""
Switch MAC Collector Script

Author: Noah Isaac Keller
Maintainer: Noah Isaac Keller
Email: nkeller@choctawnation.com

This script is designed to collect MAC addresses from a collection of
network devices. It supports various input methods, including reading IP
addresses from a text file, processing individual IP addresses,
specifying IP address ranges, and defining subnets to scan.

The script uses Netmiko for SSH connections to network devices and
retrieves MAC addresses from the MAC address tables of VLANs configured
on the devices. It supports Cisco IOS devices.

The collected MAC addresses are then exported to an XML file in a
specific format that can be used for network configuration management.

To run the script, you can specify various command-line arguments, such
as the input method, log file path, and log level.

For more details on usage and available options, please refer to the
command-line help:

Usage:
  python switch_mac_collector.py [
    -f FILE
    -i IP
    -r IP_RANGE
    -s SUBNET
    --log-file-path LOG_FILE_PATH
    --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
  ]

Options:
  -f FILE, --file FILE              Text file containing IP addresses
                                    to process.
  -i IP, --ip IP                    Single IP address to process.
  -r IP_RANGE, --ip-range IP_RANGE  IP address range to process.
                                    (e.g., 10.1.1.0-10.1.1.127)
  -s SUBNET, --subnet SUBNET        Subnet range to process.
                                    (e.g., 10.1.1.0/24)
  --log-file-path LOG_FILE_PATH     Log file path
                                    (default: config.json).
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                                    Log level (default: INFO).

The script can be configured using the 'config.json' file, which
contains parameters like the log file path and logging level.

Please make sure to install the required dependencies listed in the
script's import statements before running the script.

For any questions or issues, please contact the script author,
Noah Isaac Keller, at nkeller@choctawnation.com.
"""

__author__ = 'Noah Keller'
__maintainer__ = 'Noah Keller'
__email__ = 'nkeller@choctawnation.com'

import argparse
import functools
import getpass
import ipaddress
import json
import logging
import logging.config
import msvcrt
import os.path
import re
import sys
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, List, Optional
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

import yaml
from netmiko import (ConnectHandler, NetmikoAuthenticationException,
                     NetmikoTimeoutException)
from paramiko.ssh_exception import SSHException

# Global variables
LOGGER = logging.getLogger(__name__)


# ----------------------------------------------------------------------
#                Decorators for Logging and Error Handling
# ----------------------------------------------------------------------
def debug_log(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that logs the function call and return value."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        arguments = [repr(a) for a in args]
        keyword_arguments = [f'{k}={v!r}' for k, v in kwargs.items()]
        signature = ', '.join(arguments + keyword_arguments)
        LOGGER.debug('Calling %s(%s)', func.__name__, signature)
        result = func(*args, **kwargs)
        LOGGER.debug('"%s" returned %r', func.__name__, result)
        return result
    return wrapper


def runtime_monitor(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that measures the runtime of a function."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed_time = time.perf_counter() - start_time
        LOGGER.debug('"%s" executed in %0.2f seconds.',
                     func.__name__, elapsed_time)
        return result
    return wrapper


# ----------------------------------------------------------------------
#                 Configuration and Logging Setup
# ----------------------------------------------------------------------
def load_config(file_path: str = 'config.json') -> dict:
    """
    Load the configuration from a JSON file. If the file does not exist,
        returns an empty dictionary.

    Args:
        file_path (str, optional): The path to the configuration file.
                                    Defaults to 'config.json'.

    Returns:
        dict: The loaded configuration as a dictionary.
    """
    if not os.path.exists(file_path):
        print(f'Configuration file {file_path} not found. Using default '
              f'settings.')
    with open(file_path, 'r', encoding="utf-8") as file:
        return json.load(file)


def setup_logging(log_file_path: str, log_level: str) -> None:
    """
    Set up logging configuration.

    Args:
        log_file_path (str): The path to the log file.
        log_level (str): The desired log level.

    Returns:
        None
    """
    # Create file handler for logging
    file_handler = RotatingFileHandler(
        log_file_path,
        maxBytes=1024 * 1024,
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s][%(asctime)s][%(process)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))

    # Create console handler for logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level.upper())
    console_handler.setFormatter(logging.Formatter(
        '[%(levelname)-5s] %(message)s'))

    # Add handlers to the logger
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console_handler)
    LOGGER.setLevel(logging.DEBUG)

    if log_level != 'INFO':
        LOGGER.log(logging.INFO, 'Log level set to %s', log_level)


def add_separator_to_log(log_file_path: str, separator: str = '-' * 80):
    """
    Add a separator to the end of the log file.

    Args:
        log_file_path (str): The path to the log file.
        separator (str): The separator string to add.

    Returns:
        None
    """
    with open(log_file_path, 'a', encoding="utf-8") as log_file:
        log_file.write(separator + '\n')


# ----------------------------------------------------------------------
#                  Command Line Argument Parsing
# ----------------------------------------------------------------------
def parse_args(config: dict) -> argparse.Namespace:
    """
    Parse command line arguments.

    Args:
        config (dict): Configuration dictionary.

    Returns:
        argparse.Namespace: Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(description='Switch MAC Collector Script')

    # Required arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file',
                       help='Text file containing IP addresses to process')
    group.add_argument('-i', '--ip',
                       help='Single IP address to process')
    group.add_argument('-r', '--ip-range',
                       help='IP address range (e.g., 10.1.1.0-10.1.1.127)')
    group.add_argument('-s', '--subnet',
                       help='Subnet range (e.g., 10.1.1.0/24) to process')

    # Optional arguments
    parser.add_argument('--log-file-path',
                        default=config['log_file_path'],
                        help='Log file path (default: %(default)s)')
    parser.add_argument('--log-level',
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        default=config['logging_level'],
                        help='Log level (default: %(default)s)')

    return parser.parse_args()


# ----------------------------------------------------------------------
#                  Network Device and MAC Address Processing
# ----------------------------------------------------------------------
class DeviceManager:
    """
    A class that manages a collection of network devices.

    Attributes:
        devices (list[NetworkDevice]): A list of NetworkDevice objects
                                       representing the network devices.
        mac_addresses (set[str]): A set of MAC addresses collected from
                                  the network devices.
        failed_devices (list[str]): A list of IP addresses of devices
                                    that failed during processing.

    Methods:
        __init__(self, credentials, device_list) -> None:
            Initializes a DeviceManager object.
        process_all_devices(self) -> None:
            Processes all devices in the collection.
        process_device(self, device) -> None:
            Processes a network device to collect MAC addresses
        extract_mac_addresses(self, mac_address_table: list[dict]) -> set[str]:
            Extracts valid MAC addresses from a given MAC address table.
        is_valid_mac_address(self, mac_address: str) -> bool:
            Checks if a given string is a valid MAC address.
    """


    def __init__(self, credentials, device_list) -> None:
        """
        Initializes the DeviceManager object.

        Args:
            credentials (dict): A dictionary containing the credentials
                                for accessing the network devices.
            device_list (list): A list of IP addresses of the network
                                devices.
        """
        self.devices = [NetworkDevice(ip, credentials) for ip in device_list]
        self.mac_addresses = set()
        self.failed_devices = []

    @debug_log
    @runtime_monitor
    def process_all_devices(self) -> None:
        """
        Process all devices in the collection.

        This method iterates over each device in the collection,
            connects to the device, processes the device, and then
            disconnects from the device. If an exception occurs during
            the processing, the IP address of the device is logged as a
            failed device.

        """
        for device in self.devices:
            try:
                mac_addresses = device.process_device()
                self.mac_addresses.update(mac_addresses)
            except Exception as e:
                LOGGER.error("Error processing device %s: %s",
                             device.ip_address, str(e))
                self.failed_devices.append(device.ip_address)


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
        self.voip_vlans = []
        self.ap_vlans = []

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

        execution_time = time.perf_counter()
        LOGGER.info('Executing command "%s" on %s (%s)',
                    command, self.hostname, self.ip_address)
        try:
            output = self.connection.send_command(command, use_textfsm=fsm)
        except Exception as e:
            LOGGER.error("Error executing %s on %s: %s",
                         command, self.ip_address, e)
            output = [{'Error': e}]
        finally:
            elapsed_time = time.perf_counter() - execution_time
            LOGGER.debug('Command "%s" executed in %0.2f seconds.',
                         command, elapsed_time)

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
        LOGGER.debug("VLAN extraction in progress")
        voip_vlans = NetworkDataProcessor.extract_voip_vlans(vlan_data)
        ap_vlans = NetworkDataProcessor.extract_ap_vlans(vlan_data)
        LOGGER.debug("VLAN extraction completed.")
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

        LOGGER.debug("Discovered VoIP VLANs: %s", voip_vlans)
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

        LOGGER.debug("Discovered AP VLANs: %s", ap_vlans)
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
                    LOGGER.debug("Discovered %s on %s.",
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


class ScriptExit(Exception):
    """
    Custom exception class for script termination.

    Attributes:
        message (str): The error message associated with the exception.
        exit_code (int): The exit code to be returned when the script
                            terminates.
    """

    def __init__(self, message, exit_code=1):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


class InvalidInput(Exception):
    """
    Exception raised for invalid input.

    Attributes:
        message (str): Explanation of the error
        exit_code (int): Exit code associated with the error
    """

    def __init__(self, message, exit_code=2):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


def validate_input(args: argparse.Namespace) -> List[str]:
    """
    Validates the input arguments and returns a list of IP addresses.

    Args:
        args (argparse.Namespace): The parsed command-line arguments.

    Returns:
        List[str]: A list of validated IP addresses.

    Raises:
        InvalidInput: If no valid IP addresses are provided.
    """
    ip_addresses = []
    if args.file:
        ip_addresses = process_file(args.file)
    elif args.ip:
        ip_addresses = [args.ip]
    elif args.ip_range:
        ip_addresses = process_ip_range(args.ip_range)
    elif args.subnet:
        ip_addresses = process_subnet(args.subnet)

    if not ip_addresses:
        raise InvalidInput("No valid IP addresses provided")

    return ip_addresses


def get_credentials() -> dict:
    """
    Prompts the user to enter their username and password and returns
        them as a dictionary.

    Returns:
        A dictionary containing the username and password entered by the
            user.
    """
    username = input("Username: ")
    LOGGER.debug("Username entered: %s", username)

    try:
        # For Windows
        LOGGER.debug("Prompting user for password.")
        password = ""
        print("Password: ", end="", flush=True)
        while True:
            char = msvcrt.getch()
            if char in {b'\r', b'\n'}:  # Enter key pressed
                break
            password += char.decode()
            print(" ", end="", flush=True)
    except ImportError:
        # For Unix-like systems
        LOGGER.exception("Failed to import msvcrt module,"
                         " falling back to getpass.")
        password = getpass.getpass()
    finally:
        print()
        LOGGER.debug("Password entered.")

    return {"username": username, "password": password}


def process_text_file(file_path: str) -> List[str]:
    """
    Reads a text file and returns a list of IP addresses.

    Args:
        file_path (str): The path to the text file.

    Returns:
        List[str]: A list of IP addresses read from the file.
    """
    with open(file_path, 'r', encoding="utf-8") as f:
        ip_addresses = f.read().splitlines()
    return ip_addresses


def process_yaml_file(file_path: str) -> List[str]:
    """
    Process a YAML file and extract a list of hosts.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        List[str]: A list of host names extracted from the YAML file.
    """
    with open(file_path, 'r', encoding="utf-8") as f:
        inventory = yaml.safe_load(f.read())

    ip_addresses = []
    for host in inventory.get('hosts', []):
        if host.get('host') and is_valid_ip_address(host['host']):
            ip_addresses.append(host['host'])
        elif host.get('ip') and is_valid_ip_address(host['ip']):
            ip_addresses.append(host['ip'])
    return ip_addresses


def is_valid_ip_address(ip_address: str) -> bool:
    """
    Check if a given string is a valid IP address.

    Args:
        ip_address (str): The string to be checked.

    Returns:
        bool: True if the string is a valid IP address, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ValueError:
        return False


def process_file(file_path: str) -> List[str]:
    """
    Process the IP addresses from a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        List[str]: A list of IP addresses extracted from the file.
    """
    LOGGER.info("Processing IP addresses from file: %s", file_path)
    ip_addresses = []

    if file_path.endswith('.txt') or file_path.endswith('.text'):
        ip_addresses = process_text_file(file_path)
    elif file_path.endswith('.yml') or file_path.endswith('.yaml'):
        ip_addresses = process_yaml_file(file_path)
    else:
        LOGGER.error("Invalid file type. Exiting the script.")
        safe_exit()

    return ip_addresses


def process_subnet(subnet: str) -> List[str]:
    """
    Process a subnet and return a list of IP addresses within the subnet.

    Args:
        subnet (str): The subnet in CIDR notation.

    Returns:
        List[str]: A list of IP addresses within the subnet.

    Raises:
        InvalidInput: If the subnet format is invalid.
    """
    try:
        # strict=False allows for a subnet mask to be specified
        subnet_obj = ipaddress.IPv4Network(subnet, strict=False)
        return [str(ip) for ip in subnet_obj.hosts()]
    except ValueError as e:
        raise InvalidInput("Invalid subnet format") from e


def process_ip_range(ip_range: str) -> List[str]:
    """
    Process an IP range and return a list of summarized IP addresses.

    Args:
        ip_range (str): The IP range in the format "start_ip-end_ip".

    Returns:
        List[str]: A list of summarized IP addresses.

    Raises:
        InvalidInput: If the IP range format is invalid.
    """
    try:
        start_ip, end_ip = ip_range.split('-')
        start_ip_obj = int(ipaddress.IPv4Address(start_ip.strip()))
        end_ip_obj = int(ipaddress.IPv4Address(end_ip.strip()))
        return [str(ipaddress.IPv4Address(ip))
                for ip in range(start_ip_obj, end_ip_obj + 1)]
    except ValueError as e:
        raise InvalidInput("Invalid IP range format") from e


def export_xml(mac_address_set: set[str]) -> None:
    """
    Exports the given set of MAC addresses to an XML file.

    Args:
        mac_address_set (set[str]): The set of MAC addresses to export.

    Returns:
        None
    """
    root = create_xml_structure(mac_address_set)
    LOGGER.debug('Generated XML structure')

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string)


def create_xml_structure(mac_address_set: set[str]) -> Element:
    """
    Creates an XML structure for a given set of MAC addresses.

    Args:
        mac_address_set (set[str]): Set of MAC addresses.

    Returns:
        ET.Element: The root element of the XML structure.
    """
    LOGGER.info("Creating XML structure for %d MAC addresses.",
                len(mac_address_set))
    static_host_list_name = input('Specify static host list name: ')
    LOGGER.debug('Static host list name: %s',
                 static_host_list_name)
    static_host_list_desc = input('Specify static host list description: ')
    LOGGER.debug('Static host list description: %s',
                 static_host_list_desc)

    root = Element(
        "TipsContents", xmlns="http://www.avendasys.com/tipsapiDefs/1.0")

    SubElement(
        root,
        "TipsHeader",
        exportTime=datetime.now(timezone.utc).strftime(
            "%a %b %d %H:%M:%S UTC %Y"),
        version="6.11")
    static_host_lists = SubElement(root, "StaticHostLists")
    static_host_list = SubElement(
        static_host_lists,
        "StaticHostList",
        description=static_host_list_desc,
        name=static_host_list_name,
        memberType="MACAddress",
        memberFormat="list")
    members = SubElement(static_host_list, "Members")

    for mac_address in mac_address_set:
        create_member_element(members, mac_address)

    return root


def create_member_element(members: Element, mac_address: str) -> None:
    """
    Create a member element in the given 'members' element.

    Args:
        members (ET.Element): The parent element to which the member
                                element will be added.
        mac_address (str): The MAC address to be used for creating the
                            member element.

    Returns:
        None
    """
    SubElement(
        members,
        "Member",
        description=mac_address.replace(".", ""),
        address=mac_address.upper()
    )


def create_formatted_xml(root: Element) -> str:
    """
    Creates a formatted XML string from an ElementTree root element.

    Args:
        root (ET.Element): The root element of the ElementTree.

    Returns:
        str: The formatted XML string.
    """
    xml_string = tostring(root, encoding="UTF-8").decode("utf-8")
    xml_string = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                  + xml_string)
    dom = minidom.parseString(xml_string)
    return dom.toprettyxml(encoding="UTF-8").decode()


def save_formatted_xml(xml_string: str) -> None:
    """
    Save the formatted XML string to a file.

    Args:
        xml_string (str): The XML string to be saved.

    Returns:
        None
    """
    # Debug: Print the XML string before writing to the file
    LOGGER.debug('Saving XML to file')
    output_file_name = f'.\\smc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml'
    with open(output_file_name, 'wb') as xml_file:
        xml_file.write(xml_string.encode())


def export_txt(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Export the given set of MAC addresses to a text file.

    Args:
        mac_address_set (set[str]): Set of MAC addresses to export.
        input_file_name (str): Name of the input file.

    Returns:
        None
    """
    out_file = f'{os.path.splitext(os.path.basename(input_file_name))[0]}.txt'
    with open(f'.\\{out_file}', 'w', encoding="utf-8") as f:
        for mac_address in mac_address_set:
            f.write(mac_address + '\n')


def safe_exit(
        script_start_timer: Optional[float] = None,
        device_counter: int = 0,
        log_file_path: str = '.\\logs\\config.json'
) -> None:
    """
    Safely exits the script and logs the finishing time and script
        execution completion.

    Args:
        log_file_path (str):
        script_start_timer (Optional[float]): The start time of the
                                                script in seconds.
        device_counter (int): The number of devices processed.

    Returns:
        None
    """
    if script_start_timer and device_counter != 0:
        # Get and log finishing time
        script_elapsed_time = time.perf_counter() - script_start_timer
        LOGGER.info('The script required %0.2f seconds to finish processing on'
                    ' %d devices.', script_elapsed_time, device_counter
                    )
        LOGGER.info("Script execution completed: %s",
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Add a separator to the log file
    add_separator_to_log(log_file_path)

    # Safe close the loggers
    LOGGER.handlers[0].flush()
    LOGGER.handlers[0].close()

    sys.exit()


def main() -> None:
    """
    Entry point of the script. Executes the main logic of the switch MAC
        collector.

    Raises:
        InvalidInput: If the input arguments are invalid.
        ScriptExit: If the script encounters an error and needs to exit.
        KeyboardInterrupt: If the script is interrupted by a keyboard
                            interrupt.

    """
    config = load_config()
    args = parse_args(config)
    setup_logging(args.log_file_path, args.log_level)

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    LOGGER.info("Script execution started: %s", current_time)
    time.sleep(0.25)  # LOGGER delay

    script_start_timer = time.perf_counter()
    ip_addresses = []
    try:
        ip_addresses = validate_input(args)
        LOGGER.info("IP addresses to process: %s", ip_addresses)
        credentials = get_credentials()
        device_manager = DeviceManager(credentials, ip_addresses)
        device_manager.process_all_devices()
        export_xml(device_manager.mac_addresses)
    except InvalidInput as e:
        LOGGER.error("Invalid input: %s", e)
    except ScriptExit as e:
        LOGGER.error("Script exited: %s", e)
    except KeyboardInterrupt:
        LOGGER.error("Keyboard interrupt detected. Exiting the script.")
    finally:
        safe_exit(script_start_timer, len(ip_addresses), args.log_file_path)


if __name__ == '__main__':
    main()
