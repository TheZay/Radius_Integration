#!/usr/bin/env python
"""
macollector.py: Switch MAC Collector Script.

This script, designed by Noah Keller, is purposed to collect MAC addresses
from a network of devices. It supports reading IP addresses from files, processing
individual IPs, IP ranges, and subnets. The script leverages Netmiko for SSH
connections to Cisco IOS devices and exports collected MAC addresses to an XML
file.

Usage and command-line arguments are detailed in the script's help section.
"""

__author__ = 'Noah Keller'
__maintainer__ = 'Noah Keller'
__email__ = 'nkeller@choctawnation.com'

import argparse
import getpass
import msvcrt  # Windows only
import time
from datetime import datetime

# Local imports
from src.macollector.config_manager import load_config
from src.macollector.device_manager import DeviceManager
from src.macollector.exceptions import InvalidInput, ScriptExit
from src.macollector.exporters import export_xml
from src.macollector.file_processors import validate_input
from src.macollector.logging_setup import setup_logging
from src.macollector.utilities import safe_exit


def parse_args(config: dict) -> argparse.Namespace:
    """
    Parse command line arguments for the script.

    :param config: Configuration dictionary loaded from a JSON file.
    :type config: dict
    :return: Parsed command line arguments.
    :rtype: argparse.Namespace
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


def get_credentials(logger) -> dict:
    """
    Prompt user for username and password.

    :param logger: Logger instance for logging debug messages.
    :return: User credentials as a dictionary.
    :rtype: dict
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
        print()
        logger.debug("Password entered.")

    return {"username": username, "password": password}


def main() -> None:
    """
    Main function executing the script logic.

    Loads configuration, parses arguments, and orchestrates the MAC address
    collection and export process. Handles exceptions and ensures clean exit.

    :raises InvalidInput: If the input arguments are invalid.
    :raises ScriptExit: If the script needs to exit prematurely.
    :raises KeyboardInterrupt: If the script is interrupted by the user.
    """
    config = load_config()
    args = parse_args(config)
    logger, listener = setup_logging(args.log_file_path, args.log_level)

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info("Script execution started: %s", current_time)
    time.sleep(0.25)  # LOGGER delay

    script_start_timer = time.perf_counter()
    ip_addresses = []
    try:
        ip_addresses = validate_input(args)
        logger.info("IP addresses to process: %s", ip_addresses)
        credentials = get_credentials(logger)
        device_manager = DeviceManager(
            credentials,
            ip_addresses,
            config.get('max_threads', None)
        )
        device_manager.process_all_devices()
        export_xml(device_manager.mac_addresses)
    except InvalidInput as e:
        logger.error("Invalid input: %s", e)
    except ScriptExit as e:
        logger.error("Script exited: %s", e)
    except KeyboardInterrupt:
        logger.error("Keyboard interrupt detected. Exiting the script.")
    finally:
        safe_exit(
            len(ip_addresses),
            listener,
            args.log_file_path,
            script_start_timer
        )


if __name__ == '__main__':
    main()
