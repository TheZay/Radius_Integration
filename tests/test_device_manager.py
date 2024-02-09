import pytest

from src.macollector.device_manager import DeviceManager


@pytest.fixture
def mock_network_device(mocker):
    """
    Creates a mock NetworkDevice instance for testing.

    This fixture mocks the NetworkDevice class to simulate device interactions without real network communication.
    It setups the mock to return a predefined set of MAC addresses when process_device is called, facilitating
    testing of the DeviceManager's ability to collect MAC addresses.

    :param mocker: Pytest's built-in mocker fixture.
    :return: A MagicMock object representing a mock NetworkDevice instance.
    """
    mock = mocker.MagicMock(name="NetworkDeviceMock")
    mocker.patch("src.macollector.device_manager.NetworkDevice", return_value=mock)
    # Mock process_device to return a set of MAC addresses
    mock.process_device.return_value = {"00:11:22:33:44:55"}
    return mock


@pytest.fixture
def credentials():
    """
    Provides a static set of user credentials for testing.

    Returns a dictionary containing a username and password. These credentials are used to instantiate
    DeviceManager objects in tests, ensuring consistency across tests without accessing real credentials.

    :return: A dictionary with 'username' and 'password' keys.
    """
    return {"username": "admin", "password": "password"}


@pytest.fixture
def device_list():
    """
    Generates a predefined list of device IP addresses for testing.

    This fixture returns a list of IP addresses representing network devices. The list is used to test
    the DeviceManager's initialization and processing functions.

    :return: A list of string IP addresses.
    """
    return ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_device_manager_initialization(credentials, device_list):
    """
    Tests that DeviceManager initializes correctly with given devices and default settings.

    Validates that the DeviceManager object correctly stores the list of device IP addresses and sets
    default values for other properties, such as max_threads. This test ensures the initialization
    process works as expected with given inputs.

    :param credentials: Fixture providing user credentials.
    :param device_list: Fixture providing a list of device IP addresses.
    """
    manager = DeviceManager(credentials, device_list)
    assert len(manager.devices) == len(
        device_list
    ), "Incorrect number of devices initialized"
    assert manager.max_threads == 16, "Incorrect default max_threads value"


def test_process_all_devices_success(mock_network_device, credentials, device_list):
    """
    Verifies successful MAC address collection from all configured devices by DeviceManager.

    This test checks that DeviceManager can successfully invoke the process_device method on mock
    NetworkDevice instances and aggregate the returned MAC addresses. It uses a mock_network_device
    fixture to simulate device processing and validates the collection of MAC addresses.

    :param mock_network_device: Fixture that provides a mock NetworkDevice instance.
    :param credentials: Fixture providing user credentials.
    :param device_list: Fixture providing a list of device IP addresses.
    """
    mock_return_value = {"00:11:22:33:44:55"}
    mock_network_device.return_value.process_device.return_value = mock_return_value

    manager = DeviceManager(credentials, device_list)
    manager.process_all_devices()

    assert mock_return_value.issubset(
        manager.mac_addresses
    ), "MAC addresses not correctly collected"


def test_process_all_devices_with_errors(mocker, credentials):
    """
    Tests DeviceManager's error handling capabilities during device processing.

    Simulates scenarios where processing some devices results in errors, and verifies that DeviceManager
    correctly handles these errors by logging failed devices and still collecting MAC addresses from devices
    that do not encounter errors. This test ensures robust error handling and continuity of the MAC address
    collection process.

    :param mocker: Pytest's built-in mocker fixture.
    :param credentials: Fixture providing user credentials.
    """
    side_effects = [Exception("Device failed"), {"00:11:22:33:44:55"}]
    mock = mocker.MagicMock(name="NetworkDeviceMockWithError")
    mock.process_device.side_effect = side_effects
    mocker.patch("src.macollector.device_manager.NetworkDevice", return_value=mock)

    device_list = ["192.168.1.1", "192.168.1.2"]
    manager = DeviceManager(credentials, device_list)
    manager.process_all_devices()

    assert (
        "00:11:22:33:44:55" in manager.mac_addresses
    ), "MAC addresses not collected from successful device"
    assert len(manager.failed_devices) == 1, "Incorrect number of failed devices"


def test_process_all_devices_concurrency(mocker, credentials, device_list):
    """
    Confirms that DeviceManager processes devices concurrently.

    Ensures that DeviceManager utilizes concurrency when processing multiple devices. This test patches
    the process_device method to increment a call counter, verifying that DeviceManager makes concurrent
    calls to process devices, as indicated by the call count matching the number of devices.

    :param mocker: Pytest's built-in mocker fixture.
    :param credentials: Fixture providing user credentials.
    :param device_list: Fixture providing a list of device IP addresses.
    """
    call_counter = mocker.MagicMock()

    def process_device_side_effect(*args, **kwargs):
        call_counter()
        return {"00:11:22:33:44:55"}

    mocker.patch(
        "src.macollector.device_manager.NetworkDevice.process_device",
        side_effect=process_device_side_effect,
    )

    manager = DeviceManager(credentials, device_list)
    manager.process_all_devices()

    assert call_counter.call_count == len(device_list), (
        f"process_device called {call_counter.call_count} times; expected "
        f"{len(device_list)}"
    )
