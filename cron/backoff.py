import random
import time
from functools import wraps

from logger_partition import set_logs


def backoff(start_sleep_time=0.1, factor=2, border_sleep_time=10):

    def func_wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            x = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception:
                    sleep = min((start_sleep_time * factor ** x + random.uniform(0, 1)), border_sleep_time)
                    x += 1
                    set_logs(f'{func} delay {sleep} sec')
                    time.sleep(sleep)

        return inner

    return func_wrapper
