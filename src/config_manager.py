#!/usr/bin/env python
"""Handles loading  and parsing the configuration file."""
import json
import os.path

def load_config(file_path: str = 'configs\\config.json') -> dict:
    """
    Load the configuration from a JSON file. If the file does not exist,
        returns an empty dictionary.

    Args:
        file_path (str, optional): The path to the configuration file.
                                    Defaults to 'config.json'.

    Returns:
        dict: The loaded configuration as a dictionary.
    """
    if not os.path.exists(file_path):
        print(f'Configuration file {file_path} not found. Using default '
              f'settings.')
    with open(file_path, 'r', encoding="utf-8") as file:
        return json.load(file)
