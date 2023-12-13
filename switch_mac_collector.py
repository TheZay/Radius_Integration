"""
switch_mac_collector.py

This script is used to collect MAC addresses from network switches. It
uses the Netmiko library to establish a connection to the switch and
execute commands.

The script logs its progress, saving messages to a log file and
displaying them on the console. The log file is named using the current
date and time to ensure uniqueness.

The script handles various exceptions that can occur during the
connection and command execution process, such as authentication errors
and timeouts.

Modules:
- argparse: Used for parsing command-line arguments.
- getpass: Used for reading passwords without echoing characters.
- logging: Used for logging messages.
- msvcrt: Used for reading or writing to the console or Windows terminal.
- os.path: Used for common pathname manipulations.
- re: Used for regular expression operations.
- sys: Used for system-specific parameters and functions.
- time: Used for time-related functions.
- xml.etree.ElementTree (as ET): Used for creating or parsing XML data.
- datetime: Used for manipulating dates and times.
- typing: Used for hinting the types of variables.
- xml.dom.minidom: Used for parsing XML documents.
- yaml: Used for YAML parsing.
- netmiko: Used for connecting to and interacting with network devices.
"""

__author__ = 'Noah Isaac Keller'
__maintainer__ = 'Noah Isaac Keller'
__email__ = 'nkeller@choctawnation.com'

import argparse
import getpass
import ipaddress
import logging
import logging.config
import msvcrt
import os.path
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, List, Optional
from xml.dom import minidom

import yaml
from netmiko import (BaseConnection, ConnectHandler,
                     NetMikoAuthenticationException, NetmikoTimeoutException)
from paramiko.ssh_exception import SSHException

# Global variables
logger = logging.getLogger(__name__)


class ScriptExit(Exception):
    """Raised when the script exits"""
    def __init__(self, message, exit_code=1):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


class InvalidInput(Exception):
    """Raised when invalid input is provided"""
    def __init__(self, message, exit_code=2):
        self.message = message
        self.exit_code = exit_code
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message} (exit code: {self.exit_code})'


def create_file_handler(log_file_name: str) -> logging.Handler:
    """
    Creates a file handler for logging.

    :param log_file_name: Name of the log file
    :return: File handler
    """
    file_handler = RotatingFileHandler(
        log_file_name,
        maxBytes = 1024 * 1024,
        backupCount = 5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s][%(levelname)s][%(process)d] %(message)s',
        datefmt='%H:%M:%S'
    ))
    return file_handler


def create_console_handler() -> logging.Handler:
    """
    Creates a console handler for logging.

    :return: Console handler
    """
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(
        '[%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'))
    return console_handler


def setup_logging() -> None:
    """
    Configures logging to save messages to a file and display them on 
    the console.

    :return: None
    """
    log_file_name = f'.\\smc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_handler = create_file_handler(log_file_name)
    console_handler = create_console_handler()

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.setLevel(logging.DEBUG)


def get_credentials() -> dict:
    """
    Get user credentials: "username" and "password"

    :return: Dictionary of user credentials ("username" & "password")
    """
    username = input("Username: ")
    logger.debug("Username entered: %s", username)

    try:
        # For Windows
        logger.debug("Prompting user for password.")
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
        logger.exception("Failed to import msvcrt module,"
                         " falling back to getpass.")
        password = getpass.getpass()
    finally:
        logger.debug("Password entered.")

    return {"username": username, "password": password}


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Switch MAC Collector Script')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file',
                        help='Text file containing IP addresses to process')
    group.add_argument('-i', '--ip',
                        help='Single IP address to process')
    group.add_argument('-r', '--ip-range',
                        help='IP address range (e.g., 10.1.1.0-10.1.1.127)')
    group.add_argument('-s', '--subnet',
                        help='Subnet range (e.g., 10.1.1.0/24) to process')
    return parser.parse_args()


def validate_input(args: argparse.Namespace) -> List[str]:
    """
    Validate and process input arguments.

    :param args: Parsed command-line arguments
    :return: List of IP addresses to process
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


def process_text_file(file_path: str) -> List[str]:
    """
    Processes a text file and returns its contents as a list of IP
    addresses.

    :param file_path: Path to the text file
    :return: List of IP addresses
    """
    with open(file_path, 'r', encoding="utf-8") as f:
        ip_addresses = f.read().splitlines()
    return ip_addresses


def process_yaml_file(file_path: str) -> List[str]:
    """
    Processes a YAML file and returns its contents.

    :param file_path: Path to the YAML file
    :return: Contents of the YAML file
    """
    with open(file_path, 'r', encoding="utf-8") as f:
        inventory = yaml.safe_load(f.read())
    return [host['host'] for host in inventory.get('hosts', [])]


def process_file(file_path: str) -> List[str]:
    """
    Processes a text file containing IP addresses.

    :param file_path: Path to the text file
    :return: Dictionary of devices
    """
    logger.info("Processing IP addresses from file: %s", file_path)
    ip_addresses = []

    if file_path.endswith('.txt') or file_path.endswith('.text'):
        ip_addresses = process_text_file(file_path)
    elif file_path.endswith('.yml') or file_path.endswith('.yaml'):
        ip_addresses = process_yaml_file(file_path)
    else:
        logger.error("Invalid file type. Exiting the script.")
        safe_exit()

    return ip_addresses


def process_subnet(subnet: str) -> List[str]:
    """
    Processes a subnet range and returns a list of IP addresses.

    :param subnet: Subnet range (e.g., 10.1.1.0/24)
    :return: List of IP addresses
    """
    try:
        # strict=False allows for a subnet mask to be specified
        subnet_obj = ipaddress.IPv4Network(subnet, strict=False)
        return [str(ip) for ip in subnet_obj.hosts()]
    except ValueError as e:
        raise InvalidInput("Invalid subnet format") from e


def process_ip_range(ip_range: str) -> List[str]:
    """
    Processes an IP range and returns a list of IP addresses.
    
    :param ip_range: IP address range (e.g., 10.1.1.0-10.1.1.127)
    :return: List of IP addresses
    """
    try:
        start_ip, end_ip = ip_range.split('-')
        start_ip_obj = ipaddress.IPv4Address(start_ip.strip())
        end_ip_obj = ipaddress.IPv4Address(end_ip.strip())
        return [str(ip) for ip in
                ipaddress.summarize_address_range(start_ip_obj, end_ip_obj)]
    except ValueError as e:
        raise InvalidInput("Invalid IP range format") from e


def create_device_dict(
        ip_address: str,
        credentials: Dict[str, str]
    ) -> Dict[str, Any]:
    """
    Creates a dictionary representing a device for Netmiko.
    
    :param ip_address: IP address of the device
    :param credentials: Dictionary of user credentials
                        ("username" & "password")
    :return: Dictionary representing the device
    """
    return {
        "device_type": "cisco_ios",
        "ip": ip_address,
        "username": credentials['username'],
        "password": credentials['password'],
        "timeout": 10,
    }


def get_hostname(ssh: BaseConnection) -> str:
    """
    Retrieves the hostname of the network device.
    :param ssh: SSH object representing the connected device
    :return: Hostname of the device
    """
    try:
        hostname = ssh.find_prompt()
        return hostname.strip()
    except SSHException as e:
        logger.warning("Failed to retrieve the hostname: %s", e)
        return "Unknown"


def extract_voip_vlans(vlan_data: list[dict]) -> list[int]:
    """
    Extracts VLANs with names containing 'VOIP' from VLAN data.

    :param vlan_data: VLAN brief data
    :return: List of VOIP VLAN IDs
    """
    voip_vlans = [
        int(vlan_info['vlan_id'])
        for vlan_info in vlan_data
        if (
            'vlan_name' in vlan_info and
            re.search(r'(?i)voip', vlan_info['vlan_name']) and
            vlan_info['interfaces'] and
            is_valid_vlan_id(vlan_info['vlan_id'])
        )
    ]

    logger.info("\tVoIP VLANs found: %s", voip_vlans)
    return voip_vlans


def extract_ap_vlans(vlan_data: list[dict]) -> list[int]:
    """
    Extracts VLANs with names containing 'AP' or 'Access' from VLAN data.

    :param vlan_data: VLAN brief data
    :return: List of AP VLAN IDs
    """
    ap_vlans = [
        int(vlan_info['vlan_id'])
        for vlan_info in vlan_data
        if (
            'vlan_name' in vlan_info and
            re.search(r'(?i)ap|access\s*', vlan_info['vlan_name']) and
            vlan_info['interfaces'] and
            is_valid_vlan_id(vlan_info['vlan_id'])
        )
    ]

    logger.info("\tAP VLANs found: %s", ap_vlans)
    return ap_vlans


def is_valid_vlan_id(vlan_id: str) -> bool:
    """
    Validates a VLAN ID.

    :param vlan_id: VLAN ID to validate
    :return: True if valid, False otherwise
    """
    return vlan_id.isdigit() and 1 <= int(vlan_id) <= 4094


def extract_mac_addresses(mac_address_table: list[dict]) -> set[str]:
    """
    Extracts MAC addresses from the MAC address table.

    :param mac_address_table: MAC address table data
    :return: Set of MAC addresses
    """
    mac_addresses = set()
    po_pattern = re.compile(r'(?i)(Po|Port-Channel|Switch)')

    for mac_entry in mac_address_table:
        mac_address = mac_entry.get('destination_address')
        interfaces = mac_entry.get('destination_port')

        if not isinstance(interfaces, list):
            interfaces = [interfaces]

        for interface in interfaces:
            if (interface and not po_pattern.match(interface) and
                    mac_address and is_valid_mac(mac_address)):
                log_discovered_mac(mac_address, interface)
                mac_addresses.add(mac_address)

    return mac_addresses


def is_valid_mac(mac_address: str) -> bool:
    """
    Validates a MAC address.

    :param mac_address: MAC address to validate
    :return: True if valid, False otherwise
    """
    mac_pattern = re.compile(r"((?:[\da-fA-F]{2}[\s:.-]?){6})")
    return bool(mac_pattern.match(mac_address))


def log_discovered_mac(mac_address: str, port: str) -> None:
    """
    Logs the discovery of a MAC address on a specific port.

    :param mac_address: Discovered MAC address
    :param port: Port where the MAC address is discovered
    :return: None
    """
    logger.info("\tDiscovered %s on %s", mac_address, port)


def export_xml(mac_address_set: set[str]) -> None:
    """
    Exports MAC addresses to an XML file for ClearPass integration.

    :param mac_address_set: Set of MAC addresses
    :param input_file_name: Input file name
    :return: None
    """
    root = create_xml_structure(mac_address_set)

    # Debug: Print the generated XML structure
    xml_string_debug = ET.tostring(root, encoding="UTF-8").decode("utf-8")
    logger.debug('Generated XML structure:\n%s', xml_string_debug)

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string)


def create_xml_structure(mac_address_set: set[str]) -> ET.Element:
    """
    Creates the XML structure for exporting MAC addresses.

    :param mac_address_set: Set of MAC addresses
    :param base_file_name: Base file name
    :return: Root element of the XML
    """
    static_host_list_name = input('\n\nSpecify static host list name: ')
    static_host_list_desc = input('Specify static host list description: ')

    root = ET.Element(
        "TipsContents", xmlns="http://www.avendasys.com/tipsapiDefs/1.0")

    ET.SubElement(
        root,
        "TipsHeader",
        exportTime=datetime.now(timezone.utc).strftime(
            "%a %b %d %H:%M:%S UTC %Y"),
        version="6.11")
    static_host_lists = ET.SubElement(root, "StaticHostLists")
    static_host_list = ET.SubElement(
        static_host_lists,
        "StaticHostList",
        description=static_host_list_desc,
        name=static_host_list_name,
        memberType="MACAddress",
        memberFormat="list")
    members = ET.SubElement(static_host_list, "Members")

    for mac_address in mac_address_set:
        create_member_element(members, mac_address)

    return root


def create_member_element(members: ET.Element, mac_address: str) -> None:
    """
    Creates a member element in the XML structure.

    :param members: Members element in the XML
    :param mac_address: MAC address to add as a member
    :return: None
    """
    ET.SubElement(
        members,
        "Member",
        description=mac_address.replace(".", ""),
        address=mac_address.upper()
    )


def create_formatted_xml(root: ET.Element) -> str:
    """
    Creates formatted XML from the XML structure.

    :param root: Root element of the XML
    :return: Formatted XML string
    """
    xml_string = ET.tostring(root, encoding="UTF-8").decode("utf-8")
    xml_string = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                  + xml_string)
    dom = minidom.parseString(xml_string)
    return dom.toprettyxml(encoding="UTF-8").decode()


def save_formatted_xml(xml_string: str) -> None:
    """
    Saves the formatted XML to a file.

    :param xml_string: Formatted XML string
    :param base_file_name: Base file name
    :return: None
    """
    # Debug: Print the XML string before writing to the file
    logger.debug('Saving XML to file:\n%s', xml_string)
    output_file_name = f'.\\smc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml'
    with open(output_file_name, 'wb') as xml_file:
        xml_file.write(xml_string.encode())


def export_txt(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Exports MAC addresses to a text file.

    :param mac_address_set: Set of MAC addresses
    :param input_file_name: Input file name
    :return: None
    """
    output_file_name = f'{os.path.splitext(
        os.path.basename(input_file_name))[0]}.txt'
    with open(f'.\\{output_file_name}', 'w', encoding="utf-8") as outfile:
        for mac_address in mac_address_set:
            outfile.write(mac_address + '\n')


def safe_exit(
        script_start_timer: Optional[float] = None,
        device_counter: int = 0
    ) -> None:
    """
    Ensures a safe exit; close and flush loggers then system exit

    :param script_start_timer: Start timer of the script
    :param device_counter: Count of devices that the script ran commands on
    :return: None
    """
    if script_start_timer and device_counter != 0:
        # Get and log finishing time
        script_elapsed_time = time.perf_counter() - script_start_timer
        logger.info('The script required %0.2f seconds to finish processing on'
                    ' %d devices.', script_elapsed_time, device_counter
        )
        logger.info("Script execution completed: %s",
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Safe close the loggers
    logger.handlers[0].flush()
    logger.handlers[0].close()

    sys.exit()


def connect_to_device(device: Dict[str, Any]) -> BaseConnection:
    """
    Establishes an SSH connection to a network device.

    :param device: Dictionary representing the device
    :return: SSH connection
    """
    logger.info("===> Connecting to %s", device['ip'])
    try:
        ssh = ConnectHandler(**device)
        ssh.enable()
        logger.info("<=== Received %s", device['ip'])
        return ssh
    except Exception as e:
        raise ScriptExit(f"Failed to connect to the device: {e}") from e


def process_ip_addresses(
        ip_addresses: List[str],
        credentials: Dict[str, str]
) -> Dict[str, Any]:
    """
    Processes devices to find MAC addresses.

    :param ip_addresses: List of IP addresses to process
    :param credentials: Dictionary with 'username' and 'password'
    :return: Dictionary with 'mac_addresses' and 'failed_devices'
    """
    mac_addresses = set()
    failed_devices = []

    for ip_address in ip_addresses:
        try:
            mac_addresses.update(process_device(ip_address, credentials))
        except ScriptExit as e:
            logger.error("Failed to process %s: %s", ip_address, e)
            failed_devices.append(ip_address)

    return {"mac_addresses": mac_addresses, "failed_devices": failed_devices}


def process_device(ip_address: str, credentials: Dict[str, str]) -> set[str]:
    """
    Processes a single device to find MAC addresses.

    :param ip_address: IP address of the device
    :param credentials: Dictionary with 'username' and 'password'
    :return: List of MAC addresses found on the device
    """
    try:
        device = create_device_dict(ip_address, credentials)
        with connect_to_device(device) as ssh:
            hostname = get_hostname(ssh)
            mac_addresses = process_device_data(ssh, hostname)
            return mac_addresses
    except NetMikoAuthenticationException as e:
        raise ScriptExit("Authentication failed") from e
    except NetmikoTimeoutException as e:
        raise ScriptExit("Connection timed out") from e


def process_device_data(ssh: BaseConnection, hostname: str) -> set[str]:
    """
    Processes data on a network device to find MAC addresses.

    :param ssh: SSH object representing the connected device
    :param mac_addresses: Set of MAC addresses
    :return: None
    """
    logger.info("Processing data on %s ...", hostname)

    vlan_output = get_vlan_output(ssh)
    voip_vlans = extract_voip_vlans(vlan_output)
    ap_vlans = extract_ap_vlans(vlan_output)

    mac_addresses = set()
    for vlan_id in (voip_vlans + ap_vlans):
        mac_address_table = get_mac_address_table(ssh, vlan_id)
        extracted_mac_address = extract_mac_addresses(mac_address_table)
        mac_addresses.update(extracted_mac_address)

    logger.info("... Finished processing data on %s", hostname)
    return mac_addresses


def get_vlan_output(ssh: BaseConnection) -> list[dict]:
    """
    Retrieves VLAN data from a network device.

    :param ssh: SSH object representing the connected device
    :return: List of VLAN data
    """
    command = "show vlan brief"
    return send_command(ssh, command)


def get_mac_address_table(ssh: BaseConnection, vlan_id: int) -> list[dict]:
    """
    Retrieves MAC address table data for a specific VLAN from a network
    device.

    :param ssh: SSH object representing the connected device
    :param vlan_id: VLAN ID to query
    :return: List of MAC address table data
    """
    command = f"show mac address-table vlan {vlan_id}"
    return send_command(ssh, command)


def send_command(ssh: BaseConnection, command: str) -> list[dict]:
    """
    Sends a command to a network device and returns the output.

    :param ssh: SSH object representing the connected device
    :param command: Command to send
    :return: Output of the command
    """
    logger.info('Executing command: "%s"', command)
    execution_start_timer = time.perf_counter()
    output = ssh.send_command(command, use_textfsm=True)
    elapsed_time = time.perf_counter() - execution_start_timer
    logger.debug('Command "%s" executed in %0.2f seconds.',
                  command, elapsed_time)

    if isinstance(output, dict):
        # Handle the case where the output is a dictionary
        output = [output]
    if isinstance(output, str):
        # Handle the case where the output is a string
        output = [{'output': output}]

    return output


def disconnect_from_device(
        ssh: BaseConnection,
        device: dict,
        hostname: str
    ) -> None:
    """
    Disconnects from a network device.

    :param hostname: Hostname of the device
    :param ssh: SSH object representing the connected device
    :param device: Dictionary representing the device
    :return: None
    """
    if ssh:
        ssh.disconnect()
        logger.info("Disconnected from %s (%s)", hostname, device['ip'])


def main() -> None:
    """Main function"""
    setup_logging()
    args = parse_args()

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("Script execution started: %s", current_time)
    time.sleep(1)  # Logger delay

    # Find the MAC addresses of the devices we are looking for
    script_start_timer = time.perf_counter()
    ip_addresses = []
    try:
        ip_addresses = validate_input(args)
        credentials = get_credentials()
        result = process_ip_addresses(ip_addresses, credentials)

        if result['mac_addresses']:
            logger.info("MAC addresses found: %s", result['mac_addresses'])
            export_xml(result['mac_addresses'])

        if result["failed_devices"]:
            logger.warning("Failed to process devices: %s",
                           {', '.join(result['failed_devices'])})
    except InvalidInput as e:
        logger.error("Invalid input: %s", e)
    except ScriptExit as e:
        logger.error("Script exited: %s", e)
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting the script.")
    finally:
        safe_exit(script_start_timer, len(ip_addresses))


if __name__ == '__main__':
    main()
