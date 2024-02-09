import argparse

import pytest

from src.macollector.exceptions import ScriptExit
from src.macollector.file_processors import (
    is_valid_ip_address,
    process_file,
    process_ip_range,
    process_subnet,
    process_text_file,
    validate_input,
)


def test_validate_input_with_file(mocker):
    """
    Tests validation of input when a file is specified.

    Ensures that when a file path is provided through command line arguments, the function
    correctly processes the file to extract IP addresses. This test mocks the `process_file`
    function to return a predefined list of IP addresses, simulating the file processing
    without actual file I/O operations.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch(
        "src.macollector.file_processors.process_file", return_value=["192.168.1.1"]
    )
    args = argparse.Namespace(file="ips.txt", ip=None, ip_range=None, subnet=None)
    result = validate_input(args)
    assert result == ["192.168.1.1"], "Failed to process IPs from file"


def test_validate_input_with_ip():
    """
    Tests validation of input for a single IP address.

    Verifies that the input validation correctly handles a single IP address provided
    through command line arguments. The test checks if the function returns a list
    containing the provided IP address, ensuring the IP is correctly processed.
    """
    args = argparse.Namespace(file=None, ip="192.168.1.1", ip_range=None, subnet=None)
    result = validate_input(args)
    assert result == ["192.168.1.1"], "Failed to process IP"


@pytest.mark.parametrize(
    "ip_range,expected_ips",
    [
        ("192.168.1.1-192.168.1.3", ["192.168.1.1", "192.168.1.2", "192.168.1.3"]),
        ("192.168.1.1-3", ["192.168.1.1", "192.168.1.2", "192.168.1.3"]),
        ("192.168.1.1-2, 192.168.1.4", ["192.168.1.1", "192.168.1.2", "192.168.1.4"]),
    ],
)
def test_validate_input_with_ip_range(mocker, ip_range, expected_ips):
    """
    Tests validation of input for IP ranges.

    Parameterized test to verify that IP ranges specified through command line arguments
    are correctly processed into individual IP addresses. This test mocks the `process_ip_range`
    function to return expected lists of IP addresses for given ranges, ensuring the range
    processing logic functions as intended.

    :param mocker: Pytest fixture for mocking.
    :param ip_range: The IP range string provided as input.
    :param expected_ips: The expected list of processed IP addresses.
    """
    mocker.patch(
        "src.macollector.file_processors.process_ip_range", return_value=expected_ips
    )
    args = argparse.Namespace(file=None, ip=None, ip_range=ip_range, subnet=None)
    result = validate_input(args)
    assert result == expected_ips, "Failed to process IP range"


def test_process_text_file(mocker):
    """
    Tests extraction of IP addresses from a text file.

    Verifies that the `process_text_file` function correctly reads IP addresses from a
    provided text file and returns a list of these IPs. The test mocks file reading operations
    to simulate the presence of IP addresses in a file, checking the function's ability to
    extract them without actual file access.

    :param mocker: Pytest fixture for mocking.
    """
    test_ips = ["192.168.1.1", "192.168.1.2"]
    mocker.patch("builtins.open", mocker.mock_open(read_data="\n".join(test_ips)))
    result = process_text_file("dummy.txt")
    assert result == test_ips, "Failed to extract IPs from text file"


def test_process_subnet():
    """
    Tests generation of IP addresses from a subnet specification.

    Ensures that the `process_subnet` function accurately generates a list of IP addresses
    for a given subnet. The test provides a subnet specification and verifies that the function
    returns the expected list of IP addresses belonging to that subnet.
    """
    subnet = "192.168.1.0/30"
    expected_ips = ["192.168.1.1", "192.168.1.2"]
    result = process_subnet(subnet)
    assert result == expected_ips, "Failed to generate IPs from subnet"


def test_process_ip_range():
    """
    Tests generation of IP addresses from an IP range.

    Validates that the `process_ip_range` function correctly interprets an IP range string
    and generates a list of individual IP addresses within that range. The test checks if
    the function returns the expected list of IPs for a given range.
    """
    ip_range = "192.168.1.1-192.168.1.2"
    expected_ips = ["192.168.1.1", "192.168.1.2"]
    result = process_ip_range(ip_range)
    assert result == expected_ips, "Failed to generate IPs from IP range"


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("192.168.1.1", True),
        ("256.256.256.256", False),
    ],
)
def test_is_valid_ip_address(ip, expected):
    """
    Tests validation of IP address formats.

    Parameterized test to assess the `is_valid_ip_address` function's ability to correctly
    validate the format of various IP addresses. Each test case provides an IP address string
    and the expected boolean result indicating the validity of the IP address format.

    :param ip: The IP address string to validate.
    :param expected: The expected result of the validation (True or False).
    """
    assert is_valid_ip_address(ip) is expected, f"Incorrect validation for {ip}"


def test_process_file_nonexistent(mocker):
    """
    Tests error handling for attempts to process a non-existent file.

    Verifies that the `process_file` function raises a ScriptExit exception when it attempts
    to process a file that does not exist. This test mocks os.path.isfile to simulate the
    absence of the specified file, ensuring the function's error handling mechanism for
    non-existent files is correctly implemented.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch("os.path.isfile", return_value=False)
    with pytest.raises(ScriptExit):
        process_file("nonexistent.txt")
