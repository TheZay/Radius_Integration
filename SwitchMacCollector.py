from datetime import datetime, timezone
from netmiko import ConnectHandler, NetmikoTimeoutException, NetMikoAuthenticationException
from xml.dom import minidom
import logging
import logging.config
import msvcrt
import os.path
import re
import sys
import time
from tkinter import N
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional
from xml.dom import minidom

import yaml
from netmiko import (BaseConnection, ConnectHandler, NetMikoAuthenticationException,
                     NetmikoTimeoutException)


def setup_logging() -> None:
    """
    Configures logging to save messages to a file and display them on the console.
    :return: None
    """
    log_file_name = f'logs\\nmc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    log_file_name = f'logs\\nmc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_formatter = logging.Formatter(
        '[%(asctime)s][%(levelname)s][%(process)d][%(funcName)s:%(lineno)d] %(message)s',
        datefmt='%H:%M:%S')
    console_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s',
        datefmt='%H:%M:%S')

    file_handler = logging.FileHandler(log_file_name)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logging.getLogger().addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logging.getLogger().addHandler(console_handler)

    logging.getLogger().setLevel(logging.DEBUG)


def get_credentials() -> dict:
    """
    Get user credentials: "username" and "password"
    :return: Dictionary of user credentials ("username" & "password")
    """
    logging.debug("Prompting user for username...")
    username = input("Username: ")
    logging.debug(f"Username entered: {username}")

    try:
        # For Windows
        logging.debug("Prompting user for password.")
        password = ""
        print("Password: ", end="", flush=True)
        while True:
            char = msvcrt.getch()
            if char == b'\r' or char == b'\n':
                break
            password += char.decode()
            print(" ", end="", flush=True)
    except ImportError:
        # For Unix-like systems
        import getpass
        import tty
        password = getpass.getpass()
    finally:
        logging.debug("Password entered.")

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
            if device_filter in device['hostname'].lower() or device_filter in device['host'].lower():
                matched_devices.append(device)

        # Show matched inventory and confirm
        print_matched_inventory(matched_devices)

    inventory['hosts'] = matched_devices
    return inventory


def print_matched_inventory(matched_devices: list[dict]) -> None:
    """
    Prints the devices in the matched inventory and prompts for confirmation.
    :param matched_devices: List of devices that match the specified criteria
    :return: None
    """
    text = 'Matched inventory'
    print(f"{text}\n{'*' * len(text)}")
    for device in matched_devices:
        print(f"* HOSTNAME: {device['hostname']} - IP: {device['host']}")

    # Prompt for confirmation with a user-friendly message
    confirm = input('\nDo you want to proceed with the selected devices? (yes/no): ')
    if is_valid_user_input(confirm) and confirm.lower() != 'yes':
        logging.info("Operation aborted. Exiting the script.")
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
    voip_pattern = re.compile(r'[Vv][Oo][Ii][Pp]')
    voip_vlans = [int(vlan_info['vlan_id']) for vlan_info in vlan_data if
                  voip_pattern.search(vlan_info['vlan_name']) and len(vlan_info['interfaces']) != 0]

    logging.info(f"  VoIP VLANs found: {voip_vlans}")
    return voip_vlans


def extract_ap_vlans(vlan_data: list[dict]) -> list[int]:
    """
    Extracts VLANs with names containing 'AP' or 'Access' from VLAN data.
    :param vlan_data: VLAN brief data
    :return: List of AP VLAN IDs
    """
    ap_pattern = re.compile(r'(?i)AP|Access\s*')
    ap_vlans = [int(vlan_info['vlan_id']) for vlan_info in vlan_data if
                ap_pattern.search(vlan_info['vlan_name']) and len(vlan_info['interfaces']) != 0]

    logging.info(f"  AP VLANs found: {ap_vlans}")
    return ap_vlans


def extract_mac_addresses(mac_address_table: list[dict]) -> set[str]:
    """
    Extracts MAC addresses from the MAC address table.
    :param mac_address_table: MAC address table data
    :return: Set of MAC addresses
    """
    mac_addresses = set()
    po_pattern = re.compile(r'(?i)(Po|Port-Channel|Switch)')

    if isinstance(mac_address_table, dict):
        for mac_entry in mac_address_table:
            mac_address = mac_entry.get('destination_address')
            interface = mac_entry.get('destination_port')

            if isinstance(interface, list):
                # Handle the case where destination_port is a list
                for port in interface:
                    if not po_pattern.match(port) and mac_address and is_valid_mac(mac_address):
                        log_discovered_mac(mac_address, port)
                        mac_addresses.add(mac_address)
            elif isinstance(interface, str):
                # Handle the case where destination_port is a string
                if not po_pattern.match(interface) and mac_address and is_valid_mac(mac_address):
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
    logging.info(f'  Discovered {mac_address} on {port}')


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
    xml_string = ET.tostring(root, encoding="UTF-8").decode("utf-8")
    logging.debug(f'Generated XML:\n{xml_string}')

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string, base_file_name)


def create_xml_structure(mac_address_set: set[str], base_file_name: str) -> ET.Element:
    """
    Creates the XML structure for exporting MAC addresses.
    :param mac_address_set: Set of MAC addresses
    :param base_file_name: Base file name
    :return: Root element of the XML
    """
    root = ET.Element("TipsContents", xmlns="http://www.avendasys.com/tipsapiDefs/1.0")
    ET.SubElement(
        root,
        "TipsHeader",
        exportTime=datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"),
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
    xml_string = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + xml_string
    dom = minidom.parseString(xml_string)
    return dom.toprettyxml(encoding="UTF-8").decode()


def save_formatted_xml(xml_string: str, base_file_name: str) -> None:
    """
    Saves the formatted XML to a file.
    :param xml_string: Formatted XML string
    :param base_file_name: Base file name
    :return: None
    """
    output_file_name = f'.\\data\\{base_file_name}.xml'
    with open(output_file_name, 'wb') as xml_file:
        xml_file.write(xml_string.encode())


def export_txt(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Exports MAC addresses to a text file.
    :param mac_address_set: Set of MAC addresses
    :param input_file_name: Input file name
    :return: None
    """
    output_file_name = f'{os.path.splitext(os.path.basename(input_file_name))[0]}.txt'
    with open(f'.\\data\\{output_file_name}', 'w') as outfile:
        for mac_address in mac_address_set:
            outfile.write(mac_address + '\n')


def safe_exit(script_start_timer: Optional[float] = None, device_counter: Optional[int] = None) -> None:
    """
    Ensures a safe exit; close and flush loggers then system exit
    :param script_start_timer: Start timer of the script
    :param device_counter: Count of devices that the script ran commands on
    :return: None
    """
    if script_start_timer and device_counter:
        # Get and log finishing time
        script_elapsed_time = time.perf_counter() - script_start_timer
        logging.info(f'The script required {script_elapsed_time:0.2f} seconds'
                     f' to finish processing on {device_counter} devices.')
        logging.info(f"Script execution completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

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
    logging.info(f"===> Connecting to {hostname} ({device['host']})")
    ssh = ConnectHandler(**device)
    ssh.enable()
    logging.info(f"<=== Received {hostname} ({device['host']})")
    return ssh


def process_devices(devices: dict, credentials: dict) -> set[str]:
    """
    Processes commands on devices to find MAC addresses.
    :param devices: Dictionary of devices to connect to
    :param credentials: Dictionary of user credentials ("username" & "password")
    :return: Set of MAC addresses
    """
    mac_addresses = set()

    for device in devices['hosts']:
        device.update(devices['common_vars'])
        device.update(credentials)

        ssh: Optional[BaseConnection] = None
        hostname = None
        try:
            hostname = device['hostname']  # Assign a value to the hostname variable
            del device['hostname']

            ssh = connect_to_device(device, hostname)
            process_device_data(ssh, mac_addresses)
        except (NetmikoTimeoutException, NetMikoAuthenticationException) as e:
            logging.error(f'Error: {str(e)}')
        finally:
            if ssh and isinstance(ssh, BaseConnection) and hostname is not None:
                ssh.disconnect()
                logging.info(f"Disconnected from {hostname} ({device['host']})")

    return mac_addresses


def process_device_data(ssh: BaseConnection, mac_addresses: set[str]) -> None:
    """
    Processes data on a network device to find MAC addresses.
    :param ssh: SSH object representing the connected device
    :param mac_addresses: Set of MAC addresses
    :return: None
    """
    logging.info("Processing data on the network device ...")

    vlan_output = get_vlan_output(ssh)
    voip_vlans = extract_voip_vlans(vlan_output)
    ap_vlans = extract_ap_vlans(vlan_output)

    for vlan_id in (voip_vlans + ap_vlans):
        mac_address_table = get_mac_address_table(ssh, vlan_id)
        extracted_mac_address = extract_mac_addresses(mac_address_table)
        mac_addresses.update(extracted_mac_address)

    logging.info("... Finished processing data on the network device.")


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
    Retrieves MAC address table data for a specific VLAN from a network device.
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
    logging.info(f'Executing command: "{command}"')
    execution_start_timer = time.perf_counter()
    output = ssh.send_command(command, use_textfsm=True)
    elapsed_time = time.perf_counter() - execution_start_timer
    logging.debug(f'Command "{command}" executed in {elapsed_time:0.2f} seconds.')

    if isinstance(output, dict):
        # Handle the case where the output is a dictionary
        output = [output]
    if isinstance(output, str):
        # Handle the case where the output is a string
        output = [{'output': output}]

    return output


def disconnect_from_device(ssh: BaseConnection, device: dict, hostname: str) -> None:
    """
    Disconnects from a network device.
    :param hostname: Hostname of the device
    :param ssh: SSH object representing the connected device
    :param device: Dictionary representing the device
    :return: None
    """
    if ssh:
        ssh.disconnect()
        logging.info(f"Disconnected from {hostname} ({device['host']})")


def main(yaml_file: str) -> None:
    """
    Main function to execute the script.
    
    :param yaml_file: YAML file containing network device inventory
    :type yaml_file: str
    :return: None
    """
    setup_logging()
    logging.info(f"Script execution started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    time.sleep(1)  # Giving the loggers a chance to start before asking for user input

    # Get username and password (masks password input)
    credentials = get_credentials()

    # Read the YAML file and find inventory to run commands on
    # yaml_file = 'DCR Spa Tower.yaml'
    with open(f'data/{yaml_file}') as f:
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

    parser = argparse.ArgumentParser(description='Switch Data Retrieval Script')
    parser.add_argument('yaml_file', type=str, help='YAML file containing network device inventory')
    args = parser.parse_args()

    main(args.yaml_file)
