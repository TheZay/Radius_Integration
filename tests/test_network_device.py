from unittest.mock import patch

import pytest

from src.macollector.network_device import NetworkDevice


@pytest.fixture
def mock_connect_handler(mocker):
    """
    Creates a mock for Netmiko's ConnectHandler to simulate network device connections.

    This fixture is intended to mock the behavior of Netmiko's ConnectHandler, providing
    controlled responses for connection establishment, command execution, and other interactions.
    It sets up a mock instance with predefined return values for methods like find_prompt and
    send_command to facilitate testing without real network devices.

    :param mocker: Pytest fixture for mocking.
    :return: A mocked instance of ConnectHandler with predefined behaviors.
    """
    mock_connect_handler = mocker.patch("src.macollector.network_device.ConnectHandler")
    mock_instance = mock_connect_handler.return_value
    mock_instance.find_prompt.return_value = "MockDevice#"
    mock_instance.send_command.return_value = "Mock Command Output"
    yield mock_instance


def test_network_device_initialization():
    """
    Tests the initialization of a NetworkDevice object with given parameters.

    This test verifies that a NetworkDevice object is correctly initialized with
    specified IP address, credentials, and default values for device type and hostname.
    It ensures that the object's attributes are set as expected upon instantiation.
    """
    device = NetworkDevice(
        ip_address="192.168.1.1", credentials={"username": "user", "password": "pass"}
    )
    assert device.ip_address == "192.168.1.1"
    assert device.credentials == {"username": "user", "password": "pass"}
    assert device.device_type == "cisco_ios"
    assert device.connection is None
    assert device.hostname == "Unknown"


def test_connect_success(mock_connect_handler):
    """
    Tests successful connection to a network device.

    Verifies that the connect method updates the NetworkDevice's hostname attribute
    correctly upon a successful connection. It asserts that the hostname is set based
    on the mock device's prompt and checks that the ConnectHandler's find_prompt method
    is called as expected during the connection process.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    device = NetworkDevice(
        ip_address="192.168.1.1", credentials={"username": "user", "password": "pass"}
    )
    device.connect()
    assert (
        device.hostname == "MockDevice"
    ), "Hostname should be updated to MockDevice after successful connection"
    mock_connect_handler.find_prompt.assert_called_once()


def test_disconnect(mock_connect_handler):
    """
    Tests the disconnect method of a NetworkDevice object.

    Ensures that the disconnect method correctly calls the ConnectHandler's disconnect
    method when a device is connected. This test simulates a device connection and
    disconnection sequence to verify proper cleanup and resource release.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    # Given a NetworkDevice instance
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})

    # When connect and disconnect methods are called
    device.connect()
    device.disconnect()

    # Then the ConnectHandler's disconnect method should be called once
    mock_connect_handler.disconnect.assert_called_once()


def test_execute_command(mock_connect_handler):
    """
    Tests command execution on a network device.

    Verifies that the execute_command method correctly sends a command to the device
    and returns the expected output. It checks the method's ability to handle command
    execution through the mock ConnectHandler and validate the command's output.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    device.connect()
    result = device.execute_command("show version", fsm=False)
    assert result == [{"output": "Mock Command Output"}]


@pytest.mark.parametrize(
    "mock_extract_vlans_return_value, mock_collect_mac_addresses_return_value",
    [([10, 20], {"00:11:22:33:44:55"})],
)
def test_process_device(
    mock_extract_vlans_return_value,
    mock_collect_mac_addresses_return_value,
    mock_connect_handler,
    mocker,
):
    """
    Tests the process_device method for collecting MAC addresses from network devices.

    This parameterized test verifies that the NetworkDevice.process_device method
    correctly integrates VLAN extraction and MAC address collection functionalities.
    It mocks the VLAN extraction and MAC address collection processes to simulate
    successful device processing and asserts the collected MAC addresses match expected values.

    :param mock_extract_vlans_return_value: Mocked return value for VLAN extraction.
    :param mock_collect_mac_addresses_return_value: Mocked return value for MAC address collection.
    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch(
        "src.macollector.network_device.NetworkDataProcessor.extract_vlans",
        return_value=mock_extract_vlans_return_value,
    )
    mocker.patch(
        "src.macollector.network_device.NetworkDataProcessor.collect_mac_addresses",
        return_value=mock_collect_mac_addresses_return_value,
    )
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    device.connect()
    mac_addresses = device.process_device()
    assert mac_addresses == mock_collect_mac_addresses_return_value


def test_connect_failure(mock_connect_handler):
    """
    Tests connection failure handling in the NetworkDevice.connect method.

    Simulates a scenario where the connection to a network device fails by setting
    the find_prompt method of the mocked ConnectHandler to raise an exception. This test
    verifies that the connect method appropriately raises an exception upon failure,
    ensuring error conditions during the connection process are properly managed.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    mock_connect_handler.find_prompt.side_effect = Exception("Connection failed")
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    with pytest.raises(Exception, match="Connection failed"):
        device.connect()


def test_disconnect_without_connection(mock_connect_handler):
    """
    Tests the disconnect method without an established connection.

    Ensures that attempting to disconnect a NetworkDevice instance without an established
    connection is handled gracefully. This test verifies that the disconnect method can
    be called on a NetworkDevice instance that has not been connected without causing
    errors, reflecting proper error handling and state checking within the method.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    with pytest.raises(Exception, match="Not connected"):
        device.disconnect()


def test_execute_invalid_command(mock_connect_handler):
    """
    Tests the behavior of executing an invalid command on a network device.

    Verifies that executing an invalid or unrecognized command through the
    execute_command method properly raises an exception. This test ensures that
    command execution error handling works as expected, providing feedback when
    command execution fails.

    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    mock_connect_handler.send_command.side_effect = Exception("Invalid command")
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    device.connect()
    with pytest.raises(Exception, match="Invalid command"):
        device.execute_command("invalid command", fsm=False)


@patch("src.macollector.network_device.NetworkDataProcessor.extract_vlans")
@patch(
    "src.macollector.network_device.NetworkDataProcessor.collect_mac_addresses",
    return_value={"00:11:22:33:44:55"},
)
def test_process_device_with_failed_extraction(
    mock_extract_vlans, mock_collect_mac_addresses, mock_connect_handler
):
    """
    Tests the device processing when VLAN extraction encounters an error.

    Simulates an error condition during the VLAN extraction phase of device processing
    to verify that such errors are properly handled and reported. This test ensures that
    the process_device method is resilient to errors in the data extraction phase, correctly
    propagating exceptions to inform the caller of the failure.

    :param mock_extract_vlans: Mocked function that simulates an error in VLAN extraction.
    :param mock_collect_mac_addresses: Mocked MAC address collection function.
    :param mock_connect_handler: Fixture providing a mocked ConnectHandler instance.
    """
    mock_extract_vlans.side_effect = Exception("Failed to extract VLANs")
    device = NetworkDevice("192.168.1.1", {"username": "user", "password": "pass"})
    device.connect()
    with pytest.raises(Exception, match="Failed to extract VLANs"):
        device.process_device()
