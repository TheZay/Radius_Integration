from src.macollector.utilities import debug_log, runtime_monitor, safe_exit


def test_debug_log_decorator_logs_function_call_and_return_value(mocker):
    """
    Tests the debug_log decorator for logging function calls and their return values.

    Verifies that the `debug_log` decorator correctly logs both the entry to and the exit from
    a decorated function, including the function's return value. The test checks that the logger's
    debug method is called twice - once before the function executes and once after, confirming
    the decorator's functionality in capturing and logging debug information.

    :param mocker: Pytest fixture for mocking.
    """
    mock_logger = mocker.patch("src.macollector.utilities.logger", autospec=True)

    @debug_log
    def mock_function(a, b):
        return a + b

    result = mock_function(1, 2)

    assert result == 3
    assert mock_logger.debug.call_count == 2


def test_runtime_monitor_decorator_logs_execution_time(mocker):
    """
    Tests the runtime_monitor decorator for logging function execution time.

    Ensures that the `runtime_monitor` decorator correctly measures and logs the execution time
    of a decorated function. The test asserts that the logger's debug method is called with a message
    that includes the execution time, verifying the decorator's ability to monitor and log runtime
    information accurately.

    :param mocker: Pytest fixture for mocking.
    """
    mock_logger = mocker.patch("src.macollector.utilities.logger", autospec=True)

    @runtime_monitor
    def mock_function(a, b):
        return a + b

    result = mock_function(1, 2)

    assert result == 3
    assert mock_logger.debug.call_count == 1


def test_safe_exit_logs_script_execution_time_and_exits_script(mocker):
    """
    Tests the safe_exit utility function for logging and exiting the script gracefully.

    This test verifies that `safe_exit` logs the script's execution time, stops any running listeners,
    adds a log separator for clarity, and then exits the script using the sys.exit method. It mocks
    related functions and the sys module to check the call counts and arguments, ensuring the exit
    process is handled as expected without actually terminating the test process.

    :param mocker: Pytest fixture for mocking.
    """
    mock_logger = mocker.patch("src.macollector.utilities.logger", autospec=True)
    mock_listener = mocker.Mock()
    mock_add_separator_to_log = mocker.patch(
        "src.macollector.utilities.add_separator_to_log"
    )
    mock_sys = mocker.patch("src.macollector.utilities.sys")

    safe_exit(device_counter=5, listener=mock_listener, script_start_timer=100)

    assert mock_logger.info.call_count == 2
    assert mock_listener.stop.call_count == 1
    assert mock_add_separator_to_log.call_count == 1
    assert mock_sys.exit.call_count == 1
