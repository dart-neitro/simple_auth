import datetime
import unittest
from unittest import mock

from simple_auth.core.encryption import EncryptionMixin
from simple_auth.core.base import BaseMixin


class Encrypt(BaseMixin, EncryptionMixin):

    def __init__(self, *args, **kwargs):

        EncryptionMixin.__init__(self, *args, **kwargs)


class MyTest(unittest.TestCase):

    def test_init(self):
        with self.assertRaises(TypeError):
            Encrypt()

        with self.assertRaises(AttributeError):
            Encrypt(service_key='',
                    service_auth_key='service_auth_key')

        with self.assertRaises(AttributeError):
            Encrypt(service_key=123,
                    service_auth_key='service_auth_key')

        with self.assertRaises(AttributeError):
            Encrypt(service_key='service_key',
                    service_auth_key='')

        with self.assertRaises(AttributeError):
            Encrypt(service_key='service_key',
                    service_auth_key=111)

    @mock.patch('simple_auth.core.encryption.jwt')
    def test_encode(self, fake_jwt):
        encrypt_mixin = Encrypt(
            service_key='service_key', service_auth_key='service_auth_key')

        data = {}

        self.assertEqual(
            encrypt_mixin.encode_token(data),
            {'error': True, 'msg': 'Wrong format', 'result': None}
        )

    @mock.patch('simple_auth.core.encryption.jwt')
    def test_encode_2(self, fake_jwt):

        # wrong format data
        fake_jwt.encode = mock.MagicMock(return_value='fake_string')

        encrypt_mixin = Encrypt(
            service_key='service_key', service_auth_key='service_auth_key')

        # test with correct data
        expiration_time = datetime.datetime(2019, 4, 14, 22, 5, 0)
        data = {
            "user_id": "user_id",
            "token": "token",
            "expiration_time": expiration_time.strftime(
                encrypt_mixin.datetime_format)
        }

        self.assertEqual(
            encrypt_mixin.encode_token(data),
            {
                'result': {'encoded_string': 'fake_string'},
                'error': 0,
                'msg': ''
             }
        )

        fake_jwt.encode.assert_called_once()
        fake_jwt.encode.assert_called_with(
            {'user_id': 'user_id', 'token': 'token',
             'expiration_time': '20190414_220500'},
            'service_key', algorithm='HS256')




if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

