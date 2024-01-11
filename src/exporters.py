"""Functions for exporting data to various formats."""
import os.path
from datetime import datetime, timezone
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

from .logging_setup import LOGGER


def export_xml(mac_address_set: set[str]) -> None:
    """
    Exports the given set of MAC addresses to an XML file.

    Args:
        mac_address_set (set[str]): The set of MAC addresses to export.

    Returns:
        None
    """
    root = create_xml_structure(mac_address_set)
    LOGGER.debug('Generated XML structure')

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string)


def create_xml_structure(mac_address_set: set[str]) -> Element:
    """
    Creates an XML structure for a given set of MAC addresses.

    Args:
        mac_address_set (set[str]): Set of MAC addresses.

    Returns:
        ET.Element: The root element of the XML structure.
    """
    LOGGER.info("Creating XML structure for %d MAC addresses.",
                len(mac_address_set))
    static_host_list_name = input('Specify static host list name: ')
    LOGGER.debug('Static host list name: %s',
                 static_host_list_name)
    static_host_list_desc = input('Specify static host list description: ')
    LOGGER.debug('Static host list description: %s',
                 static_host_list_desc)

    root = Element(
        "TipsContents", xmlns="http://www.avendasys.com/tipsapiDefs/1.0")

    SubElement(
        root,
        "TipsHeader",
        exportTime=datetime.now(timezone.utc).strftime(
            "%a %b %d %H:%M:%S UTC %Y"),
        version="6.11")
    static_host_lists = SubElement(root, "StaticHostLists")
    static_host_list = SubElement(
        static_host_lists,
        "StaticHostList",
        description=static_host_list_desc,
        name=static_host_list_name,
        memberType="MACAddress",
        memberFormat="list")
    members = SubElement(static_host_list, "Members")

    for mac_address in mac_address_set:
        create_member_element(members, mac_address)

    return root


def create_member_element(members: Element, mac_address: str) -> None:
    """
    Create a member element in the given 'members' element.

    Args:
        members (ET.Element): The parent element to which the member
                                element will be added.
        mac_address (str): The MAC address to be used for creating the
                            member element.

    Returns:
        None
    """
    SubElement(
        members,
        "Member",
        description=mac_address.replace(".", ""),
        address=mac_address.upper()
    )


def create_formatted_xml(root: Element) -> str:
    """
    Creates a formatted XML string from an ElementTree root element.

    Args:
        root (ET.Element): The root element of the ElementTree.

    Returns:
        str: The formatted XML string.
    """
    xml_string = tostring(root, encoding="UTF-8").decode("utf-8")
    xml_string = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                  + xml_string)
    dom = minidom.parseString(xml_string)
    return dom.toprettyxml(encoding="UTF-8").decode()


def save_formatted_xml(xml_string: str) -> None:
    """
    Save the formatted XML string to a file.

    Args:
        xml_string (str): The XML string to be saved.

    Returns:
        None
    """
    # Debug: Print the XML string before writing to the file
    LOGGER.debug('Saving XML to file')
    output_file_name = f'smc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml'
    with open(f'data\\{output_file_name}', 'wb') as xml_file:
        xml_file.write(xml_string.encode())


def export_txt(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Export the given set of MAC addresses to a text file.

    Args:
        mac_address_set (set[str]): Set of MAC addresses to export.
        input_file_name (str): Name of the input file.

    Returns:
        None
    """
    out_file = f'{os.path.splitext(os.path.basename(input_file_name))[0]}.txt'
    with open(f'.\\{out_file}', 'w', encoding="utf-8") as f:
        for mac_address in mac_address_set:
            f.write(mac_address + '\n')
