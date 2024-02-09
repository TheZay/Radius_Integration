from xml.etree.ElementTree import Element

import pytest

from src.macollector.exporters import create_xml_structure, save_formatted_xml


def test_create_xml_structure(mocker):
    """
    Tests the creation of an XML structure from a set of MAC addresses.

    This test verifies that the `create_xml_structure` function correctly generates an XML
    Element structure representing a list of MAC addresses. It mocks user input to provide
    names and descriptions for the XML structure, then asserts that the returned result is
    an XML Element.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch("builtins.input", side_effect=["HostListName", "HostListDescription"])
    mac_address_set = {"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"}

    result = create_xml_structure(mac_address_set)

    assert isinstance(result, Element), "The result should be an Element"


def test_save_formatted_xml(mocker):
    """
    Tests the saving of a formatted XML string to a file.

    This test ensures that the `save_formatted_xml` function correctly attempts to save a
    given XML string to a file. It mocks the built-in `open` function to prevent actual file
    I/O and then verifies that `open` was called, indicating an attempt to save the XML.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch("builtins.open", mocker.mock_open())
    xml_string = "<root></root>"
    save_formatted_xml(xml_string)
    open.assert_called_once()  # Verifies that open was called


def test_save_formatted_xml_with_io_error(mocker):
    """
    Tests error handling in `save_formatted_xml` when an I/O error occurs.

    This test checks the `save_formatted_xml` function's ability to handle I/O errors
    gracefully. It mocks the built-in `open` function to raise an IOError, simulating a
    scenario where the file cannot be written to. The test then asserts that an IOError
    is indeed raised, confirming that the function propagates exceptions as expected.

    :param mocker: Pytest fixture for mocking.
    """
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("builtins.open", side_effect=IOError("Unable to write file"))
    xml_string = "<root></root>"
    with pytest.raises(IOError):
        save_formatted_xml(xml_string)
