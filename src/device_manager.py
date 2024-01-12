#!/usr/bin/env python
"""Manages multiple NetworkDevice instances."""
from .logging_setup import LOGGER
from .utilities import debug_log, runtime_monitor
from .network_device import NetworkDevice


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
