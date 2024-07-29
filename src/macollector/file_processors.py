#!/usr/bin/env python
"""
file_processors.py: Process files and extract IP addresses.

This module contains functions for processing different types of files to
extract IP addresses. It handles text files, YAML files, and subnets, and
also validates input IP addresses.

Functions include reading text and YAML files, processing subnets and IP ranges,
and validating IP addresses.
"""

import argparse
import logging
import os.path
from typing import List

import yaml
from ipaddress import IPv4Address, IPv4Network

# Local imports
from src.macollector.exceptions import InvalidInput, ScriptExit
from src.macollector.utilities import debug_log, runtime_monitor, safe_exit

# Shared logger
logger = logging.getLogger('macollector')


@debug_log
@runtime_monitor
def validate_input(args: argparse.Namespace) -> List[str]:
    """
    Validate command-line arguments and return IP addresses.

    Parses provided command-line arguments to extract IP addresses.
    It supports reading from a file, individual IP addresses, IP ranges,
    and subnets. If no valid IP addresses are found, raises InvalidInput.

    :param args: Parsed command-line arguments.
    :type args: argparse.Namespace
    :raises InvalidInput: If no valid IP addresses are provided.
    :return: List of validated IP addresses.
    :rtype: List[str]
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
    Process IP addresses from a specified file.

    Reads IP addresses from a text or YAML file. Supported file extensions are
    .txt, .text, .yml, and .yaml. Other file types will trigger an error.

    :param file_path: Path to the file containing IP addresses.
    :type file_path: str
    :return: List of IP addresses extracted from the file.
    :rtype: List[str]
    """
    if not os.path.isfile(file_path):
        raise ScriptExit("File not found.")

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


@debug_log
@runtime_monitor
def process_text_file(file_path: str) -> List[str]:
    """
    Read a text file and return a list of IP addresses.

    Opens a text file and reads each line to extract valid IP addresses.
    Invalid IPs are logged and skipped. Only supports .txt and .text files.

    :param file_path: Path to the text file.
    :type file_path: str
    :return: List of IP addresses read from the file.
    :rtype: List[str]
    """
    ip_addresses = []
    with open(file_path, 'r', encoding="utf-8") as file:
        for line in file:
            ip = line.strip()
            if is_valid_ip_address(ip):
                ip_addresses.append(ip)
            else:
                logger.warning('Skipped invalid IP address (%s) found in file '
                               '(%s).', ip, file_path)
    return ip_addresses


@debug_log
@runtime_monitor
def process_yaml_file(file_path: str) -> List[str]:
    """
    Process a YAML file and extract a list of IP addresses.

    Reads a YAML file to extract IP addresses defined under 'hosts'.
    Supports .yml and .yaml file extensions. Each host entry can have either
    'host' or 'ip' keys containing the IP address.

    :param file_path: Path to the YAML file.
    :type file_path: str
    :return: List of IP addresses extracted from the YAML file.
    :rtype: List[str]
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
    Process a subnet and return a list of IP addresses within it.

    Parses a subnet in CIDR notation and generates a list of all host IP
    addresses within that subnet. Handles both IPv4 and IPv6 subnets.

    :param subnet: The subnet in CIDR notation.
    :type subnet: str
    :raises InvalidInput: If the subnet format is invalid.
    :return: A list of IP addresses within the subnet.
    :rtype: List[str]
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
    Process an IP range and return a list of IP addresses.

    Handles IP ranges in various formats, including "start_ip-end_ip",
    "start_ip-end_ip, additional_ip", or a comma-separated list of IPs.
    Supports both continuous ranges and individual IP addresses.

    :param ip_range: The IP range in various formats.
    :type ip_range: str
    :raises InvalidInput: If the IP range format is invalid.
    :return: A list of individual IP addresses derived from the range.
    :rtype: List[str]
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
    Check if a string is a valid IPv4 address.

    Validates the provided string to determine if it represents a valid IPv4
    address.

    :param ip_address: The string to be validated.
    :type ip_address: str
    :return: True if valid, False otherwise.
    :rtype: bool
    """
    try:
        IPv4Address(ip_address)
        return True
    except ValueError:
        return False
