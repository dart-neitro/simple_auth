import sys
import os
sys.path.insert(0, os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)), '..'))

import datetime
import unittest
from unittest import mock

from simple_auth.core.encryption import (
    EncryptData, WrongFormatDataError, DecodeError)


class EncryptDataTest(unittest.TestCase):

    def test_init(self):
        with self.assertRaises(TypeError):
            EncryptData()

        with self.assertRaises(AttributeError):
            EncryptData(secret_key='')

        with self.assertRaises(AttributeError):
            EncryptData(secret_key=123)

    def test_encode(self):
        encrypt_data = EncryptData(
            secret_key='secret_key', format_data={'user_id': str})

        data = {}

        with self.assertRaises(WrongFormatDataError):
            encrypt_data.encode(data)

    @mock.patch('simple_auth.core.encryption.jwt')
    def test_encode_2(self, fake_jwt):

        # wrong format data
        fake_jwt.encode = mock.MagicMock(return_value='fake_string')

        encrypt_data = EncryptData(
            secret_key='secret_key')

        # test with correct data
        expiration_time = datetime.datetime(2019, 4, 14, 22, 5, 0)
        data = {
            "user_id": "user_id",
            "token": "token",
            "expiration_time": expiration_time.strftime(
                encrypt_data.datetime_format)
        }

        self.assertEqual(
            encrypt_data.encode(data),
            'fake_string'
        )

        fake_jwt.encode.assert_called_once()
        fake_jwt.encode.assert_called_with(
            {'user_id': 'user_id', 'token': 'token',
             'expiration_time': '20190414_220500'}, 'secret_key',
            algorithm='HS256')

    def test_decode_1(self):
        encrypt_data = EncryptData(
            secret_key='secret_key')

        encoded_string = 'encoded_string'
        with self.assertRaises(DecodeError):
            encrypt_data.decode(encoded_string)

    @mock.patch('simple_auth.core.encryption.jwt')
    def test_decode_2(self, fake_jwt):

        encrypt_data = EncryptData(
            secret_key='secret_key')

        # fake_data
        expiration_time = datetime.datetime(2019, 4, 14, 22, 5, 0)
        fake_data = {
            "user_id": "user_id",
            "token": "token",
            "expiration_time": expiration_time.strftime(
                encrypt_data.datetime_format)
        }
        fake_jwt.decode = mock.MagicMock(
            return_value=fake_data)

        # test data
        encoded_string = 'encoded_string'

        self.assertEqual(
            encrypt_data.decode(encoded_string),
            fake_data
        )

        fake_jwt.decode.assert_called_once()
        fake_jwt.decode.assert_called_with(
            'encoded_string', 'secret_key', algorithms=['HS256'])


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(EncryptDataTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

