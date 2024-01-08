import unittest

from switch_mac_collector import load_config


class TestLoadConfig(unittest.TestCase):
    def test_load_config_existing_file(self):
        # Arrange
        file_path = '..\\config.json'
        expected_config = {
            'log_file_path': '.\\logs\\switch_collector.log'
            'logging_level': 'INFO',
            'max_threads': 5,
            'retry_attempts': 3,
            'retry_delay': 5
        }

        # Act
        config = load_config(file_path)

        # Assert
        self.assertEqual(config, expected_config)

    def test_load_config_non_existing_file(self):
        # Arrange
        file_path = 'non_existing_config.json'

        # Act and Assert
        with self.assertRaises(FileNotFoundError):
            load_config(file_path)

if __name__ == '__main__':
    unittest.main()
