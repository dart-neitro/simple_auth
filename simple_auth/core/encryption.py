"""
Mixin, classes and function for work with encrypt and decrypt
"""

import datetime
import jwt
import schema

from .utilities import error_to_response, schema_wrapper


class EncryptionException(Exception):
    """
    Custom Class for Encryption Exception
    """

    pass


class EncryptionMixin:
    """
    Mixin for work with encrypt and decrypt
    """
    # datetime_format = "%Y%m%d_%H%M%S"
    secret_key = None
    algorithm = None

    def __init__(self, secret_key: str, algorithm: str='HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm

        if not secret_key or not isinstance(secret_key, str):
            raise AttributeError('secret_key must be a non-empty string')

        if not algorithm or not isinstance(algorithm, str):
            raise AttributeError('algorithm must be a non-empty string')

    def __check_encrypt_format(self, data: dict):
        """
        Method for check data format

        :param data:

        :return: result (bool)
        """

        if not isinstance(data, dict):
            return False

        key = {
            "user_id": str,
            "token": str,
            "expiration_time": schema.And(
                str, lambda x: datetime.datetime.strptime(
                    x, self.datetime_format))}
        return schema_wrapper(key=key, value=data)

    @error_to_response
    def encode_token(self, data: dict) -> str:
        """
        Encode data to sting format

        :param data: data for encoding

        :return: encoded string
        """
        # check format data
        if not isinstance(data, dict):
            return self.format(error=True, msg="data must be a dictionary")

        if not self.__check_encrypt_format(data):
            return self.format(error=True, msg="Wrong format")

        encoded_string = jwt.encode(
            data, self.secret_key, algorithm=self.algorithm)
        return self.format(result=dict(encoded_string=encoded_string))

    def decode(self, encoded_string: str) -> dict:
        """

        :param encoded_string:
        :return:
        """
        data = jwt.decode(
            encoded_string, self.secret_key, algorithms=[self.algorithm])
        return data

    def check_key(self) -> bool:
        """
        Check key for exist and available
        :return:
        """

        if not self.secret_key:
            return False
        return True

