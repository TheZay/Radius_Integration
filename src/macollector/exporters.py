#!/usr/bin/env python
"""
exporters.py: Functions for exporting data.

This module includes functions to export MAC address data to XML and text file
formats. It uses standard logging for error handling and ElementTree for XML
manipulation.

Available functions allow exporting MAC addresses to XML or text files,
creating specific XML structures, and saving the formatted XML to a file.
"""

import logging
import os.path
from datetime import datetime, timezone
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, tostring

# Shared logger
logger = logging.getLogger('macollector')


def export_xml(mac_address_set: set[str]) -> None:
    """
    Export MAC addresses to an XML file.

    Takes a set of MAC addresses and exports them to an XML file. The XML
    structure is created and then saved to a file with a generated name.

    .. note:: The XML structure is currently hardcoded for use with
              ClearPass.

    :param mac_address_set: The set of MAC addresses to export.
    :type mac_address_set: set[str]
    """
    root = create_xml_structure(mac_address_set)
    logger.debug('Generated XML structure')

    xml_string = create_formatted_xml(root)
    save_formatted_xml(xml_string)


def create_xml_structure(mac_address_set: set[str]) -> Element:
    """
    Create an XML structure from MAC addresses.

    Generates an XML structure with a specified static host list name and
    description, populated with the provided MAC addresses.

    :param mac_address_set: Set of MAC addresses.
    :type mac_address_set: set[str]
    :return: Root element of the created XML structure.
    :rtype: Element
    """
    logger.info("Creating XML structure for %d MAC addresses.",
                len(mac_address_set))
    static_host_list_name = input('Specify static host list name: ')
    logger.debug('Static host list name: %s',
                 static_host_list_name)
    static_host_list_desc = input('Specify static host list description: ')
    logger.debug('Static host list description: %s',
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
    Add a member element to the XML structure.

    :param members: Parent element to add the member element to.
    :type members: Element
    :param mac_address: MAC address for the member element.
    :type mac_address: str
    """
    SubElement(
        members,
        "Member",
        description=mac_address.replace(".", ""),
        address=mac_address.upper()
    )


def create_formatted_xml(root: Element) -> str:
    """
    Create a formatted XML string from an ElementTree root element.

    :param root: The root element of the ElementTree.
    :type root: Element
    :return: Formatted XML string.
    :rtype: str
    """
    xml_string = tostring(root, encoding="UTF-8").decode("utf-8")
    xml_string = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                  + xml_string)
    dom = minidom.parseString(xml_string)
    return dom.toprettyxml(encoding="UTF-8").decode()


def save_formatted_xml(xml_string: str) -> None:
    """
    Save formatted XML string to a file.

    :param xml_string: The XML string to be saved.
    :type xml_string: str
    """
    # Debug: Print the XML string before writing to the file
    logger.debug('Saving XML to file')
    output_file_name = f'smc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xml'
    with open(f'data\\{output_file_name}', 'wb') as xml_file:
        xml_file.write(xml_string.encode())


def export_txt(mac_address_set: set[str], input_file_name: str) -> None:
    """
    Export MAC addresses to a text file.

    .. note::
        This function is currently not used and has not been tested or
        updated since the initial implementation.

    :param mac_address_set: Set of MAC addresses to export.
    :type mac_address_set: set[str]
    :param input_file_name: Name of the input file.
    :type input_file_name: str
    """
    out_file = f'{os.path.splitext(os.path.basename(input_file_name))[0]}.txt'
    with open(f'.\\{out_file}', 'w', encoding="utf-8") as f:
        for mac_address in mac_address_set:
            f.write(mac_address + '\n')
