import time


def get_timestamp_ms() -> int:
    """`get_timestamp_ms` provides current timestamp in milliseconds

    Returns:
        int: current timestamp in milliseconds
    """
    return round(time.time_ns() / 10**6)


def in_range(ts_in: int, ts_check_against: int = None, deadline: int = 10, range: str = 'upper') -> bool:
    """[summary]

    Args:
        ts_in (int): timestamp to test in millisecond
        ts_check_against (int, optional): timestamp to test against (for debugging purposes). Defaults to current timestamp in miiliseconds.
        deadline (int, optional): deadline for range in milliseconds. Defaults to 10 milliseconds
        range (str, optional): a value between 'upper', 'lower', or 'both'. Defaults to 'upper' if invalid or not provided.

    Returns:
        bool: True if value is in upper/lower range False otherwise
    """
    if ts_check_against is None:
        ts_check_against = get_timestamp_ms()

    if range == 'lower':
        return ts_in <= (ts_check_against + deadline)
    elif range == 'both':
        return ts_in <= (ts_check_against + deadline) or ts_in >= (ts_check_against - deadline)
    else:
        return ts_in >= (ts_check_against - deadline)
