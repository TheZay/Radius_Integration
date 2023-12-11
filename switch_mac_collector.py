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

import getpass
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
from typing import Optional
from xml.dom import minidom

import yaml
from netmiko import (BaseConnection, ConnectHandler,
                     NetMikoAuthenticationException, NetmikoTimeoutException)

# Global variables
logger = logging.getLogger(__name__)


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
    log_file_name = f'.\\nmc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
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


def get_devices(inventory: dict, device_filter: str = 'all') -> dict:
    """
    Filters devices in the inventory based on a specified filter.
    :param inventory: Dictionary of devices
    :param device_filter: Filter string
    :return: Filtered inventory
    """
    device_filter = device_filter.lower()
    matched_devices = []

    if device_filter != 'all':
        for device in inventory['hosts']:
            if (device_filter in device['hostname'].lower() or
                    device_filter in device['host'].lower()):
                matched_devices.append(device)

        # Show matched inventory and confirm
        print_matched_inventory(matched_devices)

    inventory['hosts'] = matched_devices
    return inventory


def print_matched_inventory(matched_devices: list[dict]) -> None:
    """
    Prints the devices in the matched inventory and prompts for
    confirmation.
    :param matched_devices: List of devices that match the specified
                            criteria
    :return: None
    """
    text = 'Matched inventory'
    print(f"{text}\n{'*' * len(text)}")
    for device in matched_devices:
        print(f"* HOSTNAME: {device['hostname']} - IP: {device['host']}")

    # Prompt for confirmation with a user-friendly message
    confirm = input(
        '\nDo you want to proceed with the selected devices? (yes/no): ')
    if is_valid_user_input(confirm) and confirm.lower() != 'yes':
        logger.info("Operation aborted. Exiting the script.")
        safe_exit()


def is_valid_user_input(confirmation: str) -> bool:
    """
    Validates user input confirmation
    :param confirmation: user input string to validate
    :return: True if valid, False otherwise
    """
    return confirmation.lower() in {'yes', 'no'}


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
                    mac_address and
                    is_valid_mac(mac_address)):
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


def export_xml(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Exports MAC addresses to an XML file for ClearPass integration.
    :param mac_address_set: Set of MAC addresses
    :param input_file_name: Input file name
    :return: None
    """
    base_file_name = os.path.splitext(os.path.basename(input_file_name))[0]
    root = create_xml_structure(mac_address_set, base_file_name)

    # Debug: Print the generated XML structure
    xml_string_debug = ET.tostring(root, encoding="UTF-8").decode("utf-8")
    logger.debug('Generated XML structure:\n%s', xml_string_debug)

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string, base_file_name)


def create_xml_structure(
        mac_address_set: set[str],
        base_file_name: str
    ) -> ET.Element:
    """
    Creates the XML structure for exporting MAC addresses.
    :param mac_address_set: Set of MAC addresses
    :param base_file_name: Base file name
    :return: Root element of the XML
    """
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
        description=f'{base_file_name[4::]} Hotel APs and Phones',
        name=f'{base_file_name}',
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
        address=mac_address.upper())


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


def save_formatted_xml(xml_string: str, base_file_name: str) -> None:
    """
    Saves the formatted XML to a file.
    :param xml_string: Formatted XML string
    :param base_file_name: Base file name
    :return: None
    """
    # Debug: Print the XML string before writing to the file
    logger.debug('Saving XML to file:\n%s', xml_string)
    output_file_name = f'{os.path.expanduser('~\\Downloads')}\\{
        base_file_name}.xml'
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
        device_counter: Optional[int] = None
    ) -> None:
    """
    Ensures a safe exit; close and flush loggers then system exit
    :param script_start_timer: Start timer of the script
    :param device_counter: Count of devices that the script ran commands on
    :return: None
    """
    if script_start_timer and device_counter:
        # Get and log finishing time
        script_elapsed_time = time.perf_counter() - script_start_timer
        logger.info('The script required %0.2f seconds to finish processing on'
                    ' %d devices.', script_elapsed_time, device_counter
        )
        logger.info("Script execution completed: %s",
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Safe close the loggers
    logging.getLogger().handlers[0].flush()
    logging.getLogger().handlers[0].close()

    sys.exit()


def connect_to_device(device: dict, hostname: str) -> BaseConnection:
    """
    Connects to a network device using SSH.
    :param hostname: Hostname of the device
    :param device: Dictionary representing the device to connect to
    :return: SSH object
    """
    logger.info("===> Connecting to %s (%s)", hostname, device['host'])
    ssh = ConnectHandler(**device)
    ssh.enable()
    logger.info("<=== Received %s (%s)", hostname, device['host'])
    return ssh


def process_devices(devices: dict, credentials: dict) -> set[str]:
    """
    Processes commands on devices to find MAC addresses.
    :param devices: Dictionary of devices to connect to
    :param credentials: Dictionary of user credentials
                        ("username" & "password")
    :return: Set of MAC addresses
    """
    mac_addresses = set()

    for device in devices['hosts']:
        device.update(devices['common_vars'])
        device.update(credentials)

        ssh: Optional[BaseConnection] = None
        hostname = None
        try:
            # Assign a value to the hostname variable
            hostname = device['hostname']
            del device['hostname']

            ssh = connect_to_device(device, hostname)
            process_device_data(ssh, mac_addresses)
        except (NetmikoTimeoutException, NetMikoAuthenticationException) as e:
            logger.error("Error: %s", str(e))
        finally:
            if (ssh and isinstance(ssh, BaseConnection) and
                    hostname is not None):
                ssh.disconnect()
                logger.info("Disconnected from %s (%s)",
                             hostname, device['host'])

    return mac_addresses


def process_device_data(ssh: BaseConnection, mac_addresses: set[str]) -> None:
    """
    Processes data on a network device to find MAC addresses.
    :param ssh: SSH object representing the connected device
    :param mac_addresses: Set of MAC addresses
    :return: None
    """
    logger.info("Processing data on the network device ...")

    vlan_output = get_vlan_output(ssh)
    voip_vlans = extract_voip_vlans(vlan_output)
    ap_vlans = extract_ap_vlans(vlan_output)

    for vlan_id in (voip_vlans + ap_vlans):
        mac_address_table = get_mac_address_table(ssh, vlan_id)
        extracted_mac_address = extract_mac_addresses(mac_address_table)
        mac_addresses.update(extracted_mac_address)

    logger.info("... Finished processing data on the network device.")


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
        logger.info("Disconnected from %s (%s)", hostname, device['host'])


def main(yaml_file: str  = ".\\DCR Spa Tower.yaml") -> None:
    """
    Main function to execute the script.
    
    :param yaml_file: YAML file containing network device inventory
    :type yaml_file: str
    :return: None
    """
    setup_logging()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("Script execution started: %s", current_time)
    time.sleep(1)  # Logger delay

    # Get username and password (masks password input)
    credentials = get_credentials()

    # Read the YAML file and find inventory to run commands on
    # yaml_file = 'DCR Spa Tower.yaml'
    with open(yaml_file, encoding="utf-8") as f:
        inventory = yaml.safe_load(f.read())
    dev_filter = input('\n\nSpecify device filter: ')
    devices = get_devices(inventory, dev_filter)
    device_counter = len(devices['hosts'])

    # Find the MAC addresses of the devices we are looking for
    script_start_timer = time.perf_counter()
    mac_addresses = process_devices(devices, credentials)

    # Export the MAC addresses into an XML file for ClearPass to import
    export_xml(mac_addresses, yaml_file)
    # export_txt(mac_addresses, yaml_file)

    # Script completion into a safe exit
    safe_exit(script_start_timer, device_counter)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Switch MAC Collector Script')
    parser.add_argument(
        'yaml_file',
        type=str,
        help='YAML file containing network device inventory'
    )
    args = parser.parse_args()

    main(args.yaml_file)
