"""
Mixin, classes and function for work with encrypt and decrypt
"""

import datetime
import jwt
from jwt.exceptions import DecodeError
import schema

from .utilities import error_to_response, schema_wrapper


class EncryptionException(Exception):
    """
    Custom Class for Encryption Exception
    """

    pass


class WrongFormatDataError(Exception):
    """
    Custom Class for Encryption Exception
    """

    pass


# class DecodeError(Exception):


class EncryptData:
    """
    Class provide methods for work with encrypt and decrypt data
    """

    # for work with end user
    secret_key = None
    algorithm = None
    format_data = None

    def __init__(self, secret_key: str,
                 format_data: dict, algorithm: str = 'HS256'):
        """
        :param secret_key: key for encrypting and decrypting
        :param format_data: format data for checking
        :param algorithm: encrypting algorithm
        """

        self.secret_key = secret_key
        self.algorithm = algorithm
        self.format_data = format_data

        if not secret_key or not isinstance(secret_key, str):
            raise AttributeError('secret_key must be a non-empty string')

        if not algorithm or not isinstance(algorithm, str):
            raise AttributeError('algorithm must be a non-empty string')

    def encode(self, data: dict) -> str:
        """
        Encode data to sting format

        :param data: data for encoding

        :return: encoded string
        """

        # check format data
        if not isinstance(data, dict):
            raise WrongFormatDataError("The data must be a dictionary")

        if not schema_wrapper(key=self.key, value=data):
            raise WrongFormatDataError("Wrong data format")

        encoded_string = jwt.encode(
            data, self.secret_key, algorithm=self.algorithm)

        return encoded_string

    def decode(self, encoded_string: str) -> str:
        """
        String to data

        :param encoded_string:

        :return:
        """
        try:
            data = jwt.decode(
                encoded_string, self.secret_key, algorithms=[self.algorithm])
        except DecodeError:
            raise DecodeError("Wrong string for decoding")

        if not schema_wrapper(key=self.key, value=data):
            raise WrongFormatDataError("Wrong data format")

        return data



class EncryptionMixin:
    """
    Mixin for work with encrypt and decrypt
    """

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

    @property
    def __format_service_data(self):
        """
        Get format data for service part

        :return:
        """

        key = {
            "user_id": str,
            "token": str,
            "expiration_time": schema.And(
                str, lambda x: datetime.datetime.strptime(
                    x, self.datetime_format))}
        return key

    #@error_to_response
    def encode_token(self, data: dict) -> str:
        return self.__encode(
            key=self.__format_service_data,
            data=data, secret_key=self.service_key,
            algorithm=self.service_algorithm)

    #@error_to_response
    def __encode(self, data: dict, key: dict,
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

    def decode_token(self, encoded_string: str) -> dict:
        return self.__decode(encoded_string,
                             key=self.__format_service_data,
                             secret_key=self.service_key,
                             algorithm=self.service_algorithm)

    def __decode(self, encoded_string: str, key: dict,
                 secret_key: str, algorithm: str) -> str:
        """

        :param encoded_string:
        :return:
        """
        try:
            data = jwt.decode(
                encoded_string, secret_key, algorithms=[algorithm])
        except DecodeError:
            return self.format(error=True, msg="Wrong string for decoding")

        if not schema_wrapper(key=key, value=data):
            return self.format(error=True, msg="Wrong format")

        return self.format(result=data)

    def check_key(self) -> bool:
        """
        Check key for exist and available
        :return:
        """

        if not self.secret_key:
            return False
        return True

