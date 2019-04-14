import datetime


def check_datetime_format(timestamp, format):
    try:
        datetime.datetime.strptime(timestamp, format)
        return True
    except:
        pass
    return False
