import datetime


from .base import BaseMixin
from .utilities import check_datetime_format


class RemoteUserCheck(BaseMixin):
    secret_key = None
    server_auth = None
    datetime_format = "%Y%m%d_%H%M%S"
    timestamp_delta = datetime.timedelta(seconds=5)

    def __init__(self, secret_key, server_auth):
        self.secret_key = secret_key
        self.server_auth = server_auth

    def check_expiration_time(self, expiration_time: str) -> bool:
        """
        Check session's time life. This method reduce number of requests to
        authentication server

        :param expiration_time:

        :return:
        """

        # existing
        if not expiration_time:
            return False

        # format
        if not check_datetime_format(expiration_time, self.datetime_format):
            return False

        expiration_time = datetime.datetime.strptime(
            expiration_time, self.datetime_format)

        current_time_stamp = datetime.datetime.now()

        if expiration_time - self.timestamp_delta > current_time_stamp:
            return True

        return False

    def check(self, user_id: str, cookies: str, expiration_time: str) -> dict:
        """
        Validate cookies

        :param user_id: user_id
        :param cookies: string
        :param expiration_time: cookies expiration time

        :return: checking result
        """
        if not self.check_expiration_time(expiration_time):
            return self.format(error=True, msg="Time is out for cookies")

        return self.format()
