#!/usr/bin/env python
"""This module contains functions to process files and extract IP
    addresses."""
import argparse
from ipaddress import IPv4Address, IPv4Network
from typing import List
import yaml

from .exceptions import InvalidInput
from .logging_setup import LOGGER
from .utilities import debug_log, runtime_monitor, safe_exit


@debug_log
@runtime_monitor
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
        ip_addresses = [args.ip] if is_valid_ip_address(args.ip) else safe_exit()
    elif args.ip_range:
        ip_addresses = process_ip_range(args.ip_range)
    elif args.subnet:
        ip_addresses = process_subnet(args.subnet)

    if not ip_addresses:
        raise InvalidInput("No valid IP addresses provided")

    return ip_addresses


@debug_log
@runtime_monitor
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


@debug_log
@runtime_monitor
def process_text_file(file_path: str) -> List[str]:
    """
    Reads a text file and returns a list of IP addresses.

    Args:
        file_path (str): The path to the text file.

    Returns:
        List[str]: A list of IP addresses read from the file.
    """
    ip_addresses = []
    with open(file_path, 'r', encoding="utf-8") as file:
        for line in file:
            ip = line.strip()
            if is_valid_ip_address(ip):
                ip_addresses.append(ip)
            else:
                LOGGER.warning('Skipped invalid IP address (%s) found in file '
                               '(%s).', ip, file_path)
    return ip_addresses


@debug_log
@runtime_monitor
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


@debug_log
@runtime_monitor
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
        subnet_obj = IPv4Network(subnet, strict=False)
        return [str(ip) for ip in subnet_obj.hosts()]
    except ValueError as e:
        raise InvalidInput("Invalid subnet format") from e


@debug_log
@runtime_monitor
def process_ip_range(ip_range: str) -> List[str]:
    """
    Process an IP range and return a list of IP addresses. This range
    can be in the format "<ip>-<ip>", "<ip>-<ip>, <ip>" or a
    comma-separated list of IP addresses.

    Args:
        ip_range (str): The IP range in the format "<ip>-<ip>",
        "<ip>-<ip>, <ip>" or a comma-separated list of IP addresses.

    Returns:
        List[str]: A list of summarized IP addresses.

    Raises:
        InvalidInput: If the IP range format is invalid.
    """
    ip_addresses = []

    # Split by comma to handle individual IPs and ranges
    parts = [part.strip() for part in ip_range.split(',')]

    for part in parts:
        if '-' in part:
            # Handle ranges
            try:
                start_ip, end_ip = part.split('-')
                start_ip_obj = IPv4Address(start_ip.strip())
                # Check if end_ip is in short format
                # (e.g., "192.168.0.1-3")
                if '.' not in end_ip:
                    # end_ip = start_ip[:start_ip.rfind('.') + 1] + end_ip
                    end_ip = '.'.join(start_ip.split('.')[:-1] +
                                      [end_ip.strip()])
                end_ip_obj = IPv4Address(end_ip)

                while start_ip_obj <= end_ip_obj:
                    ip_addresses.append(str(start_ip_obj))
                    start_ip_obj += 1

            except ValueError as e:
                raise InvalidInput("Invalid IP range format") from e
        else:
            # Handle individual IPs
            try:
                ip_addresses.append(str(IPv4Address(part)))
            except ValueError as e:
                raise InvalidInput(f"Invalid IP address {part}") from e

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
        IPv4Address(ip_address)
        return True
    except ValueError:
        return False
