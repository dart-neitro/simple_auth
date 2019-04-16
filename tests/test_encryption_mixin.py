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

        # wrong format data
        fake_jwt.encode_token = mock.MagicMock(return_value='fake_string')
        data = {}

        self.assertEqual(
            encrypt_mixin.encode_token(data),
            {'error': True, 'msg': 'Wrong format', 'result': None}
        )




if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

