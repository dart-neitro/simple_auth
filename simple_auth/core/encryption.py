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
    # for work with end user
    service_key = None
    service_algorithm = None

    # for work with auth service
    service_auth_key = None
    service_auth_algorithm = None

    def __init__(self, service_key: str, service_auth_key: str,
                 service_algorithm: str='HS256',
                 service_auth_algorithm: str= 'HS256',
                 ):

        self.service_key = service_key
        self.service_algorithm = service_algorithm
        self.service_auth_key = service_auth_key
        self.service_auth_algorithm = service_auth_algorithm

        if not service_key or not isinstance(service_key, str):
            raise AttributeError('secret_key must be a non-empty string')

        if not service_algorithm or not isinstance(service_algorithm, str):
            raise AttributeError('algorithm must be a non-empty string')

        if not service_auth_key or not isinstance(service_auth_key, str):
            raise AttributeError('secret_key must be a non-empty string')

        if not service_auth_algorithm or not isinstance(service_auth_algorithm, str):
            raise AttributeError('algorithm must be a non-empty string')

    def __check_encrypt_format(self, data: dict):
        """
        Method for check data format

        :param data:

        :return: result (bool)
        """

    #@error_to_response
    def encode_token(self, data: dict) -> str:
        key = {
            "user_id": str,
            "token": str,
            "expiration_time": schema.And(
                str, lambda x: datetime.datetime.strptime(
                    x, self.datetime_format))}

        return self.__encode(
            key=key, data=data, secret_key=self.service_key,
            algorithm=self.service_algorithm)

    #@error_to_response
    def __encode(self, key: dict, data: dict,
                 secret_key: str, algorithm: str) -> str:
        """
        Encode data to sting format

        :param key: data for encoding
        :param data: data for encoding
        :param secret_key: secret_key for encoding
        :param algorithm: algorithm for encoding

        :return: encoded string
        """

        # check format data
        if not isinstance(data, dict):
            return self.format(error=True, msg="data must be a dictionary")

        if not schema_wrapper(key=key, value=data):
            return self.format(error=True, msg="Wrong format")

        encoded_string = jwt.encode(
            data, secret_key, algorithm=algorithm)

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

