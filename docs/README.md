# MACollector: Automated MAC Address Collection Tool

**Author:** Noah Keller  
**Maintainer:** Noah Keller  
**Email:** [nkeller@choctawnation.com](mailto:nkeller@choctawnation.com)

## Introduction

Welcome to `MACollector`, an essential tool for network engineers in the Radius Integration project. This Python utility
streamlines the collection of MAC addresses from network switches and integrates seamlessly with ClearPass for advanced
network access control and management. `MACollector` enhances both efficiency and security in network operations,
eliminating the need for manual data collection.

### What is Radius Integration and ClearPass?

Radius Integration refers to the integration of networked devices with a Radius server for authentication and access
control. ClearPass is a network access control (NAC) solution that uses this information for enhanced security and
management.

## Table of Contents

- [Introduction](#introduction)
- [Key Features](#key-features)
- [System Requirements](#system-requirements)
- [Getting Started](#getting-started)
    - [Installation](#installation)
    - [Configuration](#configuration)
    - [Running the Script](#running-the-script)
- [Usage Guide](#usage-guide)
    - [Input Methods](#input-methods)
    - [Logging and Output](#logging-and-output)
- [Command Line Examples](#command-line-examples)
- [File Format Examples](#file-format-examples)
- [Troubleshooting](#troubleshooting)
    - [Connection Timeout or Failure](#1-connection-timeout-or-failure)
    - [Incorrect MAC Address Data](#2-incorrect-mac-address-data)
    - [XML Export Issues](#3-xml-export-issues)
    - [Dependency Errors](#4-dependency-errors)
    - [Script Execution Errors](#5-script-execution-errors)
- [Feedback and Support](#feedback-and-support)
- [Contribution Guidelines](#contribution-guidelines)
- [Future Plans and Roadmap](#future-plans-and-roadmap)
- [License](#license)

## Description

`MACollector` is a comprehensive Python package for automating the collection of MAC addresses from network switches.
It's designed to simplify network management tasks, particularly in Radius Integration and ClearPass projects.

## Key Features

- Automated MAC address collection from Cisco IOS network devices.
- Supports multiple input methods: file, single IP, IP range, subnet.
- Flexible logging and output options: Export to XML or text files.
- User-friendly: Minimal interaction required, suitable for users unfamiliar with advanced networking tools.

## System Requirements

- Python 3.6 or later ([download here](https://www.python.org/downloads/))
- Dependencies: `netmiko`, `paramiko`, `pyyaml`, `ipaddress` (install via pip)

You can install the dependencies using [pip](https://pip.pypa.io/en/stable/):

```bash
pip install netmiko paramiko pyyaml ipaddress
```

## Getting Started

### Installation

1. **Clone or Download the Repository**:
    - For users familiar with Git, clone the repository using `git clone [repository-url]`.
    - Alternatively, download the ZIP file from the remote repository and extract it on your machine.

2. **Install Python**: Ensure Python 3.6 or newer is installed on your machine.
   Visit [Python's official site](https://www.python.org/downloads/) for installation instructions.

3. **Install Dependencies**: Open a terminal or command prompt and navigate to the script's directory.
   Run `pip install -r requirements.txt` to install necessary dependencies.

### Configuration

The `MACollector` script offers customization through its configuration file, `config.json`, located in the `configs`
directory. This file allows you to set parameters for logging and threading. Below is a description of each configurable
item in `config.json`:

#### `config.json` Explained

```json
{
  "log_file_path": "logs\\macollector.log",
  "logging_level": "INFO",
  "max_threads": 16
}
```

- **log_file_path**: Specifies the file path where the log file will be saved. The default path
  is `"logs\\macollector.log"`.
- **logging_level**: Sets the verbosity level of the logs. Available options
  are `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`, and `"CRITICAL"`. The default level is `"INFO"`.
- **max_threads**: Determines the maximum number of threads for concurrent processing of network devices. Adjust this to
  optimize performance based on your system's capabilities. The default is `16`.

#### Customizing Configuration

To tailor the script to your needs, you can edit the `config.json` file with your preferred settings. For instance, if
you require more detailed logs, change `"logging_level"` to `"DEBUG"`. If you are working with a large number of network
devices and your system can support higher concurrency, consider increasing `"max_threads"`.

Ensure that you save the `config.json` file after making changes to apply them the next time you run the script.

## Usage Guide

### Running the Script

Navigate to the `scripts` directory and execute the `macollector.cmd` script:

```bash
# Navigate to the scripts directory
cd scripts

# Run the script with options
./macollector.cmd [options]
```

If you are using Linux or macOS, you can run the `macollector.sh` script instead:

```bash
# Navigate to the scripts directory
cd scripts

# Run the script with options
./macollector.sh [options]
```

Please refer to the [Command Line Examples](#command-line-examples) section for detailed usage examples.

### Options

The script provides several command-line options to customize its behavior:

- `-f FILE, --file FILE`: Use a text file containing IP addresses for processing.
- `-i IP, --ip IP`: Specify a single IP address for processing.
- `-r IP_RANGE, --ip-range IP_RANGE`: Define an IP address range for processing (e.g., 10.1.1.0-10.1.1.127).
- `-s SUBNET, --subnet SUBNET`: Specify a subnet range for processing (e.g., 10.1.1.0/24).
- `--log-file-path LOG_FILE_PATH`: Set a custom path for the log file.
- `--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set the logging level for the console output.

### Input Methods

- **File**: Provide a text or YAML file containing IP addresses.
- **Single IP**: Process a specific IP address.
- **IP Range**: Specify a range of IP addresses.
- **Subnet**: Define a subnet range for processing.

### Logging and Output

- The script's logging behavior can be adjusted in the `config.json` file.
- Collected MAC addresses are exported to either an XML file for integration with ClearPass or a plain text file.

## Command Line Examples

Note that the examples below are for Windows users. If you are using
Linux or macOS, you can run the `macollector.sh` script instead.

```bash
# Process a Single IP Address:
.\macollector.cmd -i 192.168.1.1
```

![Single IP Address](images/single_ip_example.jpg)

```bash
# Process a range of IP Addresses plus a single IP Address:
# Note: The range and single IP are separated by a comma.
#       *If you type a space after the comma, use quotes around the range.*
.\macollector.cmd -r "10.1.1.1, 10.1.1.10-20"
```

![IP Range](images/ip_range_example.jpg)

```bash
# Process a range of IP Addresses:
# Note: The range of IPs can be fully typed out or use shorthand notation as shown in the above example.
.\macollector.cmd -r 10.1.1.10-10.1.1.20
```

![IP Range](images/ip_range_example_2.jpg)

```bash
# Process a Subnet:
.\macollector.cmd -s 192.168.0.0/24  # CIDR Notation
```

![Subnet](images/subnet_example.jpg)

```bash
# Process IP Addresses from a Text File and log to a custom Log File:
.\macollector.cmd -f ip_list.txt --log-file-path custom_log_file_path.log
```

![Text File & Log Path](images/text_file_and_log_path_change.jpg)

```bash
# Change the Console Handler (prints to screen) Log Level to DEBUG
.\macollector.cmd -f ip_list.txt --log-level DEBUG
```

![Text File & Log Level](images/text_file_and_log_level_change.jpg)

```bash
# Process IP Addresses from a YAML File:
.\macollector.cmd -f ip_list.yml
```

![Yaml File](images/yml_file_example.jpg)

```bash
# Process IP Addresses from an Enhanced YAML File:
.\macollector.cmd -f ip_list.yaml
```

![Enhanced Yaml File](images/enhanced_yaml_file_example.jpg)

## File Format Examples

Here's an example of what the text file (`ip_list.txt`) and the YAML file (`inventory.yml`) should look like for the
Switch MAC Collector Script:

### Text Files (`ip_list.txt`)

```text
192.168.1.1
192.168.1.2
192.168.1.3
```

In the text file, each line represents an IP address of a network device. You can add as many IP addresses as needed,
one per line.

### YAML File (`inventory.yml`)

```yaml
hosts:
  - ip: 192.168.1.1
  - ip: 192.168.1.2
  - host: 192.168.1.3
```

In the YAML file, you define a list of hosts under the "hosts" key. Each host in the list should have a "host" key with
its corresponding IP address. You can add or remove hosts as necessary.

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

In this enhanced YAML file, you can also specify a "hostname" for each host in addition to the "host" key. This allows
you to associate a friendly name with each IP address, making it easier to identify the devices in your network.

#### YAML File Explained

1. The 'host' key or 'ip' key is required for each entry.
2. The 'host' key is intended for the hostname or fully qualified domain name (FQDN) of the network
   device.
    - The 'host' key may also be used to specify the IP address, but it is recommended to use the 'ip' key for
      clarity and consistency.
    - The hostname is optional and can be omitted as the script will ignore it. However, it can be useful for
      reference and organization.
3. The 'ip' key is used to specify the IP address of the network device.
    - An IP address is **required** for each entry and must be valid for the script to process it.

These files serve as input sources for the Switch MAC Collector Script, allowing you to specify the IP addresses of the
network devices you want to process.

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

- Check the MACollector's write permissions in the directory where the XML file is being saved.
- Ensure the MACollector's configuration for the XML export format is correct.

### 4. Dependency Errors

**Problem**: The MACollector package fails to run due to missing Python dependencies.

**Solution**:

- Make sure Python 3.6 or newer is installed.
- Run `pip install -r requirements.txt` to install all required dependencies, ensuring the `requirements.txt` file
  includes `netmiko`, `paramiko`, and `pyyaml`.

### 5. Script Execution Errors

**Problem**: General errors or unexpected behavior during script execution.

**Solution**:

- Check the console output and log files for error messages.
- Ensure that the latest version of the script is being used.
- Review the command-line arguments to ensure they are correctly formatted.

## Feedback and Support

If your issue is not listed in the [Troubleshooting](#troubleshooting) section or persists after trying the suggested
solutions,
please reach out for support
at [nkeller@choctawnation.com](mailto:nkeller@choctawnation.com). When reporting an issue, include the following details
for a quicker resolution:

- Description of the problem and when it occurs.
- Any error messages or output from the console.
- Steps you've already taken to try and solve the issue.

## Contribution Guidelines

We welcome and encourage contributions from the community to improve this project. To ensure a smooth process, please
follow these guidelines:

1. **Fork the Repository**: Before making any contributions, fork this repository to your GitHub account.

2. **Create a Branch**: For each feature, bug fix, or improvement, create a separate branch in your forked repository.

3. **Commit Changes**: Make your changes and commit them with clear and concise commit messages.

4. **Test**: Ensure that your changes do not introduce new issues and that they align with the project's objectives.

5. **Submit a Pull Request**: Once your changes are ready, submit a pull request to the `dev` branch of this
   repository. Provide a detailed description of your changes and why they are valuable.

6. **Code of Conduct**: Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) when participating in this project.

7. **Licensing**: By contributing, you agree that your contributions will be licensed under the same license as this
   project.

8. **Review**: Your pull request will be reviewed by project maintainers. Be prepared to make any necessary adjustments
   based on feedback.

9. **Merge**: Once your pull request is approved, it will be merged into the main repository.

Thank you for contributing to this project and helping make it better for everyone!

## Future Plans and Roadmap

Yes, there are plans to expand and improve this project in the future. Here are some of the ideas in mind:

- Retrying failed connections and error handling for more robust operation.
- Support for additional network device types and vendors.
- Improved logging and output options for more flexibility.
- Support for additional input methods and file formats.
- User interface and interactive mode for easier operation.
- Advanced configuration options for customizing the script's behavior.
- Enhanced security features and best practices for network management.
- Advanced reporting and analytics for network device data collection.
- Enhanced testing and quality assurance for a more stable and reliable tool.

## License

This project is licensed under [GPLv3+](../LICENSE).
See the [LICENSE](../LICENSE) file for more details.
