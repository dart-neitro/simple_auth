import sys
import os
sys.path.insert(0, os.path.join(
    os.path.dirname(
        os.path.abspath(__file__)), '..'))

import datetime

import unittest
from unittest import mock

from simple_auth.core.auth import RemoteUserCheck


class MyTest(unittest.TestCase):

    def test_expiration_time(self):
        ruc = RemoteUserCheck(server_auth=None)
        user_cookies = {
            "user_id": "1",
            "cookies": "123",
            "expiration_time": ""
        }
        now = datetime.datetime.now()

        timestamp = now + datetime.timedelta(seconds=60)
        timestamp = timestamp.strftime(ruc.datetime_format)

        self.assertEqual(
            ruc.check_expiration_time(timestamp),
            True
        )

        timestamp = now.strftime(ruc.datetime_format)

        self.assertEqual(
            ruc.check_expiration_time(timestamp),
            False
        )

        self.assertEqual(
            ruc.check_expiration_time(""),
            False
        )

        self.assertEqual(
            ruc.check(**user_cookies).get("error"),
            True
        )

    @mock.patch('simple_auth.core.auth.datetime')
    def test_user_id(self, fake_datetime):
        ruc = RemoteUserCheck(server_auth=None)
        now = datetime.datetime(2019, 4, 14, 22, 0, 0)
        expiration_time = datetime.datetime(2019, 4, 14, 22, 5, 0)
        fake_datetime.datetime = mock.MagicMock()

        fake_datetime.datetime.now = mock.MagicMock(return_value=now)
        fake_datetime.datetime.strptime = datetime.datetime.strptime

        user_cookies = {
            "user_id": "",
            "cookies": "cookies",
            "expiration_time": expiration_time.strftime(ruc.datetime_format)
        }

        self.assertEqual(
            ruc.check(**user_cookies).get("error"),
            True
        )

        user_cookies["user_id"] = "user_id"

        self.assertEqual(
            ruc.check(**user_cookies).get("error"),
            False
        )

    @mock.patch('simple_auth.core.auth.datetime')
    def test_cookies(self, fake_datetime):
        ruc = RemoteUserCheck(server_auth=None)
        now = datetime.datetime(2019, 4, 14, 22, 0, 0)
        expiration_time = datetime.datetime(2019, 4, 14, 22, 5, 0)
        fake_datetime.datetime = mock.MagicMock()

        fake_datetime.datetime.now = mock.MagicMock(return_value=now)
        fake_datetime.datetime.strptime = datetime.datetime.strptime

        user_cookies = {
            "user_id": "user_id",
            "cookies": "",
            "expiration_time": expiration_time.strftime(ruc.datetime_format)
        }

        self.assertEqual(
            ruc.check(**user_cookies).get("error"),
            True
        )

        user_cookies["cookies"] = "cookies"

        self.assertEqual(
            ruc.check(**user_cookies).get("error"),
            False
        )



if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

