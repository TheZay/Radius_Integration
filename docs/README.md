# Switch MAC Collector Script

**Author:** Noah Isaac Keller  
**Maintainer:** Noah Isaac Keller  
**Email:** <nkeller@choctawnation.com>

Welcome to the **Switch MAC Collector Script**, a specialized tool developed to address the real-world needs of network engineers. Born out of the necessity to automate the manual and time-intensive task of fetching MAC addresses from switches, this script is a cornerstone of our Radius Integration project.

The inception of this tool was driven by the challenge faced during the integration of network device data into ClearPass for enhanced network access control and management. By automating the collection of MAC addresses and exporting them in an XML format compatible with ClearPass, this script significantly streamlines the process, reducing manual effort and minimizing the potential for error.

Designed with the day-to-day workflows of network engineers in mind, this Python-based utility not only simplifies a crucial aspect of network management but also plays a vital role in ensuring the efficiency and reliability of network operations.

Whether you're involved in network configuration, auditing, or setting up sophisticated access control systems, the Switch MAC Collector Script is your go-to solution for seamless data collection and integration.

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
- [Command Line Examples](#command-line-examples)
- [File Format Examples](#file-format-examples)
- [Troubleshooting](#troubleshooting)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)

## Description

The Switch MAC Collector Script is a Python-based tool primarily aimed at network engineers, developed to streamline the collection of MAC addresses from network switches. This script is a key component in network management tasks, particularly in projects involving Radius Integration and ClearPass.

### Interactive and Configurable

- **User Interaction**: Early in its execution, the script prompts the user for network device login credentials (username and password). This ensures secure and authorized access to the network devices for MAC address collection.
- **Command-Line Flexibility**: In addition to the initial credential input, the script is operated primarily via command-line arguments. This design allows for versatile and dynamic use cases, accommodating various network scenarios through different input methods.

### Core Functionalities

- **Automated Data Collection**: The script automates the tedious process of collecting MAC addresses from network switches, significantly improving efficiency and accuracy.
- **Diverse Input Methods**: It accepts a range of inputs - from individual IP addresses to subnets - making it suitable for networks of varying sizes and complexities.
- **ClearPass Integration**: A notable feature is its capability to format the collected MAC addresses into an XML file, facilitating easy integration with ClearPass for advanced network access control.

### Practical Use Cases

- **Network Audits and Security**: The script plays a vital role in network audits and enhancing security protocols by ensuring accurate and up-to-date device data.
- **Streamlined Network Management**: By automating data collection and integrating smoothly with existing systems like ClearPass, the script elevates network management efficiency.

### Intended Workflow

This script is designed to interact minimally with the user while providing maximum functionality. Once the credentials are entered, the rest of the process is largely automated, guided by the specified command-line arguments. This approach makes it a user-friendly yet powerful tool in the hands of network professionals.

## Features

- Collect MAC addresses from Cisco IOS network devices.
- Multiple input methods (file, single IP, IP range, subnet).
- Flexible logging configuration.
- Export collected MAC addresses to an XML file.

## Requirements

Before using the script, make sure you have the following requirements installed:

- Python 3.6 or [newer](https://www.python.org/downloads/)
- Dependencies listed in the script (`netmiko`, `paramiko`, `yaml`, `ipaddress`)

You can install the dependencies using [pip](https://pip.pypa.io/en/stable/):

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
- `--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Log level (default: INFO) for the console handler only.

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

## Command Line Examples

```bash
# Process a Single IP Address:
python switch_mac_collector.py -i 192.168.1.1
```

![Single IP Address](images/single_ip_example.jpg)

```bash
# Process an IP Range:
python switch_mac_collector.py -r 10.1.1.10-10.1.1.20
```

![IP Range](images/ip_range_example.jpg)

```bash
# Process a Subnet:
python switch_mac_collector.py -s 192.168.0.0/24
```

![Subnet](images/subnet_example.jpg)

```bash
# Process IP Addresses from a Text File and log to a custom Log File:
python switch_mac_collector.py -f ip_list.txt --log-file-path custom_log_file_path.log
```

![Text File & Log Path](images/text_file_and_log_path_change.jpg)

```bash
# Change the Console Handler (prints to screen) Log Level to DEBUG
python switch_mac_collector.py -f ip_list.txt --log-level DEBUG
```

![Text File & Log Level](images/text_file_and_log_level_change.jpg)

```bash
# Process IP Addresses from a YAML File:
python switch_mac_collector.py -f ip_list.yml
```

![Yaml File](images/yml_file_example.jpg)

```bash
# Process IP Addresses from an Enhanced YAML File:
python switch_mac_collector.py -f ip_list.yaml
```

![Enhanced Yaml File](images/enhanced_yaml_file_example.jpg)

## File Format Examples

Here's an example of what the text file (`ip_list.txt`) and the YAML file (`inventory.yml`) should look like for the Switch MAC Collector Script:

### Text Files (`ip_list.txt`)

```text
192.168.1.1
192.168.1.2
192.168.1.3
```

In the text file, each line represents an IP address of a network device. You can add as many IP addresses as needed, one per line.

### YAML File (`inventory.yml`)

```yaml
hosts:
  - ip: 192.168.1.1
  - ip: 192.168.1.2
  - host: 192.168.1.3
```

In the YAML file, you define a list of hosts under the "hosts" key. Each host in the list should have a "host" key with its corresponding IP address. You can add or remove hosts as necessary.

### Enhanced YAML File (`inventory.yaml`)

```yaml
hosts:
  - host: Switch1
    ip: 192.168.1.1
  - host: Switch2
    ip: 192.168.1.2
  - host: Switch3
    ip: 192.168.1.3
```

In this enhanced YAML file, you can also specify a "hostname" for each host in addition to the "host" key. This allows you to associate a friendly name with each IP address, making it easier to identify the devices in your network.

These files serve as input sources for the Switch MAC Collector Script, allowing you to specify the IP addresses of the network devices you want to process.

## Troubleshooting

Encountering issues while using the Switch MAC Collector Script? Here are some common problems and their solutions:

### 1. Connection Timeout or Failure

**Problem**: The script fails to connect to a network switch, resulting in a timeout or connection failure error.

**Solution**:

- Check if the IP address of the switch is correct and reachable.
- Ensure that the network device is powered on and connected to the network.
- Verify that the SSH service is enabled on the device.
- Confirm that the username and password entered are correct.

### 2. Incorrect MAC Address Data

**Problem**: The MAC addresses collected do not match expectations or seem incorrect.

**Solution**:

- Ensure that the IP range or subnet specified covers the intended devices.
- Verify that the network devices are configured correctly and are reporting MAC addresses accurately.

### 3. XML Export Issues

**Problem**: The MAC addresses are collected but not properly exported to an XML file.

**Solution**:

- Check the script's write permissions in the directory where the XML file is being saved.
- Ensure the script's configuration for the XML export format is correct.

### 4. Dependency Errors

**Problem**: The script fails to run due to missing Python dependencies.

**Solution**:

- Make sure Python 3.6 or newer is installed.
- Run `pip install -r requirements.txt` to install all required dependencies, ensuring the `requirements.txt` file includes `netmiko`, `paramiko`, and `pyyaml`.

### 5. Script Execution Errors

**Problem**: General errors or unexpected behavior during script execution.

**Solution**:

- Check the console output and log files for error messages.
- Ensure that the latest version of the script is being used.
- Review the command-line arguments to ensure they are correctly formatted.

### Still Need Help?

If your issue is not listed here or persists after trying the suggested solutions, please reach out for support at <nkeller@choctawnation.com>. When reporting an issue, include the following details for a quicker resolution:

- Description of the problem and when it occurs.
- Any error messages or output from the console.
- Steps you've already taken to try and solve the issue.

## Contribution Guidelines

We welcome and encourage contributions from the community to improve this project. To ensure a smooth process, please follow these guidelines:

1. **Fork the Repository**: Before making any contributions, fork this repository to your GitHub account.

2. **Create a Branch**: For each feature, bug fix, or improvement, create a separate branch in your forked repository.

3. **Commit Changes**: Make your changes and commit them with clear and concise commit messages.

4. **Test**: Ensure that your changes do not introduce new issues and that they align with the project's objectives.

5. **Submit a Pull Request**: Once your changes are ready, submit a pull request to the `main` branch of this repository. Provide a detailed description of your changes and why they are valuable.

6. **Code of Conduct**: Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) when participating in this project.

7. **Licensing**: By contributing, you agree that your contributions will be licensed under the same license as this project.

8. **Review**: Your pull request will be reviewed by project maintainers. Be prepared to make any necessary adjustments based on feedback.

9. **Merge**: Once your pull request is approved, it will be merged into the main repository.

Thank you for contributing to this project and helping make it better for everyone!

## License

This project is licensed under the [MIT License](..\LICENSE) - see the [LICENSE](..\LICENSE) file for details.
