import datetime

import unittest

from core.auth import RemoteUserCheck


class MyTest(unittest.TestCase):

    def test_1(self):
        ruc = RemoteUserCheck(secret_key='secret_key', server_auth=None)
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


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(MyTest)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

