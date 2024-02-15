import pytest

from src.macollector.data_processor import NetworkDataProcessor


def test_extract_voip_vlans():
    """
    Test VOIP VLAN extraction from a list of VLAN data.

    Verifies that the extract_voip_vlans function correctly identifies and extracts
    VLAN IDs designated for VOIP services based on their names from a given list
    of VLAN information dictionaries.

    The test provides a sample list of VLAN data and checks if the function returns
    the expected list of VOIP VLAN IDs.
    """
    vlan_data = [
        {"vlan_id": "100", "vlan_name": "VOICE VLAN", "interfaces": ["Gi1/0/1"]},
        {"vlan_id": "200", "vlan_name": "DATA VLAN", "interfaces": ["Gi1/0/2"]},
    ]
    expected_voip_vlans = [100]
    assert (
        NetworkDataProcessor.extract_voip_vlans(vlan_data) == expected_voip_vlans
    ), "VOIP VLAN extraction failed"


def test_extract_ap_vlans():
    """
    Test AP VLAN extraction from a list of VLAN data.

    Ensures that the extract_ap_vlans function accurately identifies and extracts
    VLAN IDs used for Access Points (AP) based on their names from a provided list
    of VLAN information dictionaries.

    The test uses a predefined list of VLAN data and validates if the function yields
    the expected list of AP VLAN IDs.
    """
    vlan_data = [
        {"vlan_id": "300", "vlan_name": "AP VLAN", "interfaces": ["Gi1/0/3"]},
        {"vlan_id": "400", "vlan_name": "MANAGEMENT VLAN", "interfaces": ["Gi1/0/4"]},
    ]
    expected_ap_vlans = [300]
    assert (
        NetworkDataProcessor.extract_ap_vlans(vlan_data) == expected_ap_vlans
    ), "AP VLAN extraction failed"


def test_collect_mac_addresses(monkeypatch):
    """
    Test MAC address collection across specified VLANs.

    Validates the collect_mac_addresses function's ability to collect MAC addresses
    from a mock command executor across specified VLAN IDs. The test mocks the
    command executor function to return a predefined list of MAC addresses and
    checks if the collection matches the expected set of MAC addresses.

    :param monkeypatch: Pytest fixture to mock functions and methods.
    """
    vlan_ids = [100, 200]
    mock_command_output = [
        {"destination_address": "AA:BB:CC:DD:EE:FF", "destination_port": "Gi1/0/1"},
        {"destination_address": "11:22:33:44:55:66", "destination_port": "Gi1/0/2"},
    ]

    # Define a mock function for command_executor
    def mock_command_executor(command, **kwargs):
        if "show mac address-table vlan" in command:
            return mock_command_output
        return []

    # Directly use the mock_command_executor when calling collect_mac_addresses
    extracted_macs = NetworkDataProcessor.collect_mac_addresses(
        vlan_ids, mock_command_executor
    )
    expected_macs = {"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}
    assert (
        extracted_macs == expected_macs
    ), "MAC address collection did not return the expected results"


@pytest.mark.parametrize(
    "mac_address_table, expected_macs",
    [
        (
            [
                {
                    "destination_address": "AA:BB:CC:DD:EE:FF",
                    "destination_port": "Gi1/0/1",
                }
            ],
            {"AA:BB:CC:DD:EE:FF"},
        ),
        (
            [{"destination_address": "GG:HH:II:JJ:KK:LL", "destination_port": "Po1"}],
            set(),
        ),
    ],
)
def test_extract_mac_addresses(mac_address_table, expected_macs):
    """
    Test MAC address extraction from MAC address table entries.

    Parameterized test that verifies the extract_mac_addresses function can correctly
    parse a list of MAC address table entries and extract a set of unique MAC addresses.
    Each test case provides a sample MAC address table and the expected set of extracted
    MAC addresses.
    """
    extracted_macs = NetworkDataProcessor.extract_mac_addresses(mac_address_table)
    assert (
        extracted_macs == expected_macs
    ), "MAC address extraction did not match expected results"


@pytest.mark.parametrize(
    "mac_address, expected_result",
    [
        ("AA:BB:CC:DD:EE:FF", True),
        ("00:00:00:00:00:00", True),
        ("GG:HH:II:JJ:KK:LL", False),  # Invalid MAC
        ("AA:BB:CC:DD:EE:FG", False),  # Invalid characters
    ],
)
def test_is_valid_mac_address(mac_address, expected_result):
    """
    Test MAC address validation.

    Parameterized test that checks the is_valid_mac_address function for correctly
    validating the format and content of various MAC addresses. Each test case
    provides a MAC address string and the expected boolean result indicating whether
    the MAC address is valid or not.
    """
    assert (
        NetworkDataProcessor.is_valid_mac_address(mac_address) == expected_result
    ), f"MAC address validation failed for {mac_address}"


def test_is_voip_vlan():
    """
    Test identification of VOIP VLANs.

    Verifies that the is_voip_vlan function can accurately determine whether a given
    VLAN information dictionary represents a VOIP VLAN based on its name.
    """
    vlan_info = {"vlan_id": "100", "vlan_name": "VOICE VLAN", "interfaces": ["Gi1/0/1"]}
    assert (
        NetworkDataProcessor.is_voip_vlan(vlan_info) is True
    ), "Failed to identify VOIP VLAN"


def test_is_ap_vlan():
    """
    Test identification of AP VLANs.

    Confirms that the is_ap_vlan function correctly identifies VLANs designated for
    Access Points (AP) from a given VLAN information dictionary based on its name.
    """
    vlan_info = {"vlan_id": "300", "vlan_name": "AP VLAN", "interfaces": ["Gi1/0/3"]}
    assert (
        NetworkDataProcessor.is_ap_vlan(vlan_info) is True
    ), "Failed to identify AP VLAN"


@pytest.mark.parametrize(
    "vlan_id, expected_result",
    [
        ("100", True),
        ("4096", False),  # Out of range
        ("abc", False),  # Not a digit
    ],
)
def test_is_valid_vlan_id(vlan_id, expected_result):
    """
    Test VLAN ID validation.

    Parameterized test assessing the is_valid_vlan_id function's capability to validate
    the format and value range of VLAN IDs. Each test case provides a VLAN ID string
    and the expected boolean result indicating the validity of the VLAN ID.
    """
    assert (
        NetworkDataProcessor.is_valid_vlan_id(vlan_id) == expected_result
    ), f"VLAN ID validation failed for {vlan_id}"
