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
import getpass
import msvcrt
import time
from datetime import datetime

from .logging_setup import LOGGER, setup_logging
from .exceptions import InvalidInput, ScriptExit
from .device_manager import DeviceManager
from .exporters import export_xml
from .config_manager import load_config
from .file_processors import validate_input
from .utilities import safe_exit


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
