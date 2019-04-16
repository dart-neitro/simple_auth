import sys
import datetime
from functools import wraps

import schema


def check_datetime_format(timestamp, format):
    try:
        datetime.datetime.strptime(timestamp, format)
        return True
    except:
        pass
    return False


def error_to_response(f):
    """
    This decorator provided exceptions processing for critical cases

    :param f: class method

    :return: class method
    """

    @wraps(f)
    def wrapper(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except Exception as e:
            return self.format(error=True, msg="Unknown error")

    return wrapper


def schema_wrapper(key, value, logger=None, logger_level='debug') -> bool:
    """
    Wrapper for schema with logger

    :param key: schema for checking
    :param value: value
    :param logger: logger
    :param logger_level: logger level

    :return: result of check (bool)
    """

    if isinstance(logger_level, str):
        logger_level = logger_level.lower()

    try:
        schema.Schema(key).validate(value)
        return True
    except Exception as e:
        if logger and hasattr(logger, logger_level):
            method = getattr(logger, logger_level)
            method(e)
            method(sys.exc_info())
            logger.exception(e)
    return False
