#!/usr/bin/env python
"""
config_manager.py: Load and parse configuration.

This module loads configurations from a JSON file, using standard logging
for error reporting and the json module for parsing.

The main function, `load_config`, loads configurations from a specified
JSON file. If the file is missing, has invalid JSON, or other errors occur,
an empty dictionary is returned and errors are logged.

The default configuration file path is 'configs\\config.json', but can be
overridden.
"""

import json
import logging
import os.path

# Shared logger
logger = logging.getLogger('macollector')


def load_config(file_path: str = 'configs\\config.json') -> dict:
    """
    Load JSON configuration from a file.

    Opens the specified JSON file and loads its contents into a dictionary.
    If the file doesn't exist, contains invalid JSON, or other errors occur,
    the issue is logged and an empty dictionary is returned.

    :param file_path: Path to the configuration file.
    :type file_path: str
    :returns: Configuration as a dictionary or empty dict on error.
    :rtype: dict
    """
    if not os.path.exists(file_path):
        logger.error('Configuration file %s does not exist',
                     file_path)
        return {}

    try:
        with open(file_path, 'r', encoding="utf-8") as config_file:
            return json.load(config_file)
    # return empty dictionary if a JSONDecodeError occurs
    except json.JSONDecodeError as e:
        logger.error('Error parsing configuration file %s: %s',
                     file_path, e)
    # return empty dictionary if any other exception occurs
    except Exception as e:
        logger.error('Error loading configuration file %s: %s',
                     file_path, e)

    return {}
