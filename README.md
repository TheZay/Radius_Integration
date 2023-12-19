# Switch MAC Collector Script

**Author:** Noah Isaac Keller  
**Maintainer:** Noah Isaac Keller  
**Email:** <nkeller@choctawnation.com>

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Input Methods](#input-methods)
- [Logging](#logging)
- [Output](#output)
- [Examples](#examples)
- [Disclaimer](#disclaimer)

## Description

The Switch MAC Collector Script is a Python script designed to collect MAC addresses from a collection of network devices. It supports various input methods, including reading IP addresses from a text file, processing individual IP addresses, specifying IP address ranges, and defining subnets to scan. The collected MAC addresses are then exported to an XML file in a specific format that can be used for network configuration management.

## Features

- Collect MAC addresses from Cisco IOS network devices.
- Multiple input methods (file, single IP, IP range, subnet).
- Flexible logging configuration.
- Export collected MAC addresses to an XML file.

## Requirements

Before using the script, make sure you have the following requirements installed:

- Python 3.6 or newer
- Dependencies listed in the script (`netmiko`, `paramiko`, `yaml`, `ipaddress`)

You can install the dependencies using pip:

```bash
pip install netmiko paramiko pyyaml
```

## Installation

1. Clone or download the script to your local machine.

2. Install the required dependencies as mentioned in the "Requirements" section.

## Usage

Run the script with the following command:

```bash
python switch_mac_collector.py [options]
```

### Options

- `-f FILE, --file FILE`: Text file containing IP addresses to process.
- `-i IP, --ip IP`: Single IP address to process.
- `-r IP_RANGE, --ip-range IP_RANGE`: IP address range (e.g., 10.1.1.0-10.1.1.127) to process.
- `-s SUBNET, --subnet SUBNET`: Subnet range (e.g., 10.1.1.0/24) to process.
- `--log-file-path LOG_FILE_PATH`: Log file path (default: config.json).
- `--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Log level (default: INFO).

## Configuration

The script can be configured using the `config.json` file, which contains parameters like the log file path and logging level.

## Input Methods

- **File**: Provide a text file containing IP addresses to process.
- **Single IP**: Process a single specified IP address.
- **IP Range**: Specify an IP address range (e.g., 10.1.1.0-10.1.1.127) to process.
- **Subnet**: Define a subnet range (e.g., 10.1.1.0/24) to process.

## Logging

The script supports flexible logging configuration. You can specify the log file path and log level using command-line options.

## Output

The collected MAC addresses are exported to an XML file in a specific format that can be used for network configuration management. You can also export them to a text file.

## Examples

```bash
# Process a Single IP Address:
python switch_mac_collector.py -i 192.168.1.1

# Process an IP Range:
python switch_mac_collector.py -r 10.1.1.10-10.1.1.20

# Process a Subnet:
python switch_mac_collector.py -s 192.168.0.0/24

# Process IP Addresses from a Different Configuration File:
python switch_mac_collector.py -f ip_list.txt --log-file-path custom_config.json

# Change the Log Level to Debug
python switch_mac_collector.py -f ip_list.txt --log-level DEBUG

# Process IP Addresses from a YAML File:
python switch_mac_collector.py -f inventory.yml

# Process IP Addresses from a Different Input File Type:
python switch_mac_collector.py -f hosts.yaml
```

## Disclaimer

This script is provided as-is without any warranties. Use it at your own risk and review the code to ensure it fits your specific use case.
