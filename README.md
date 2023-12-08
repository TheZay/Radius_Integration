# Switch Data Retrieval Script Documentation

## Overview

The Switch Data Retrieval Script is designed to collect data from network switches in an environment, with a specific focus on devices related to Voice over IP (VoIP) and Access Points (APs). The primary goal is to extract MAC addresses associated with these devices, allowing for the creation of an XML file. This XML file can be utilized in network authentication systems, such as ClearPass, for Radius integration.

## Prerequisites

Before using the script, make sure you have the following:

- Python installed (version 3.6 or later)
- Netmiko library installed (`pip install netmiko`)
- YAML file containing the network device inventory

## Installation

User the package manager [pip](https://pip.pypa.io/en/stable/) to install netmiko.

```bash
pip install netmiko
```

## Usage

1. **Configure Logging:**
   - The script is configured to save messages to both a file and the console. Log files are named with a timestamp.

2. **Retrieve User Credentials:**
   - The script will prompt you for the username and password required to access network devices.

3. **Load Network Device Inventory:**
   - Provide the path to the YAML file containing the network device inventory.

4. **Specify Device Filter (Optional):**
   - Optionally, you can specify a filter to select specific devices for processing.

5. **Run the Script:**
   - Execute the script, and it will connect to each device, retrieve VLAN brief information, and identify VoIP and AP VLANs.

6. **Export MAC Addresses:**
   - The script will export the collected MAC addresses into an XML file for further integration.

## Command Line Arguments

- `yaml_file`: Path to the YAML file containing network device inventory.

## Examples

```bash
# Run the script with a YAML file in the current directory
python SwitchMacCollector.py "DCR Spa Tower.yaml"

# Run the script with a YAML file in a different directory
python SwitchMacCollector.py "/path/to/your/yaml/file.yaml"

# Run the script with a YAML file in the parent directory
python SwitchMacCollector.py "../another_directory.yaml"
```

## Disclaimer

This script is provided as-is without any warranties. Use it at your own risk and review the code to ensure it fits your specific use case.
