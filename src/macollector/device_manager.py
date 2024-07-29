#!/usr/bin/env python
"""
device_manager.py: Manages multiple network devices for concurrent processing.

This module contains the DeviceManager class, which is responsible for
managing a collection of network devices. It initializes NetworkDevice
objects and manages their concurrent processing using a thread pool. The
class also collects MAC addresses from the devices and handles errors
that occur during processing.

The DeviceManager class allows for specifying credentials, a list of
device IP addresses, and the maximum number of threads for concurrent
processing.
"""

import logging
import traceback
from concurrent.futures import as_completed, ThreadPoolExecutor

# Local imports
from src.macollector.network_device import NetworkDevice
from src.macollector.utilities import debug_log, runtime_monitor

# Global logger variable
logger = logging.getLogger('macollector')


class DeviceManager:
    """
    Manages and processes a collection of network devices concurrently.

    The DeviceManager initializes and handles multiple NetworkDevice
    instances, collecting MAC addresses and handling errors during
    processing. It employs a ThreadPoolExecutor for concurrent device
    processing.

    :param credentials: Authentication credentials for network devices.
    :type credentials: dict
    :param device_list: IP addresses of the network devices to manage.
    :type device_list: list
    :param max_threads: Maximum number of threads to use for concurrent
                        processing. Defaults to 16.
    :type max_threads: int
    :ivar devices: The initialized network device objects.
    :vartype devices: list[NetworkDevice]
    :ivar max_threads: The maximum number of threads to use for
                       processing.
    :vartype max_threads: int
    :ivar mac_addresses: Collected MAC addresses from all devices.
    :vartype mac_addresses: set[str]
    :ivar failed_devices: IP addresses of devices that failed during
                          processing.
    :vartype failed_devices: list[str]
    """

    def __init__(self, credentials: dict, device_list: list, max_threads: int = 16):
        """
        Initializes the DeviceManager with given credentials,
        device list, and concurrency settings.
        """
        self.devices = [NetworkDevice(ip, credentials) for ip in device_list]
        self.max_threads = max_threads
        self.mac_addresses = set()
        self.failed_devices = []

    @debug_log
    @runtime_monitor
    def process_all_devices(self) -> None:
        """
        Processes all network devices concurrently using multiple
        threads.

        This method sets up a ThreadPoolExecutor to handle each device's
        MAC address collection process. It updates the set of MAC
        addresses and logs any errors encountered during processing.

        :return: None
        """
        # Create a ThreadPoolExecutor with the maximum number of threads
        with ThreadPoolExecutor(max_workers=self.max_threads) as tpe:
            # Create a future for each device's process_device method
            # The process_device method is expected to return a list of MAC addresses
            # The futures dictionary maps each future to its corresponding device
            futures = {tpe.submit(device.process_device): device for device in self.devices}

        # Iterate over the futures as they complete
        for future in as_completed(futures):
            # Get the device associated with the completed future
            device = futures[future]
            try:
                # Get the result of the future, which should be a list
                # of MAC addresses
                mac_addresses = future.result()
                # Add the MAC addresses to the set of all MAC addresses
                self.mac_addresses.update(mac_addresses)
            except Exception as e:
                # If an error occurred while processing the device, log
                # the error and add the device's IP address to the list
                # of failed devices
                logger.error("Error processing device %s: %s",
                             device.ip_address, str(e))
                traceback.print_exc()  # More detailed error traceback
                self.failed_devices.append(device.ip_address)
