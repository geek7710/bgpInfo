#!/usr/bin/env python
import unittest
from unittest import mock
import bgp


class raise_exception(Exception):
    print("I Crashed!!!")

class test_VerifyUserInput(unittest.TestCase):
    @mock.patch("bgp.subprocess")
    def test_subprocess_fail(self, mock_subprocess):
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (
            '10.255.251.250\tmbus-cid-rtr1.reyes.remote.hms.cdw.com\tmbus-cid-rtr1',
            "error")}
        process_mock.configure_mock(**attrs)
        mock_subprocess.side_effect = raise_exception
        try:
            proc = mock_subprocess(
                    ['cat', '/etc/hosts'], stdout=mock_subprocess.PIPE)
            stdout = proc.communicate()[0]
            print(stdout)
        except Exception as err:
            print(err)

    @mock.patch("bgp.VerifyUserInput")
    def test_verify_user_input(self, mock_user_input):
        instance = mock_user_input('mbus-cid-rtr1')
        stdout = instance.verify_etc_hosts()


if __name__ == '__main__':
    unittest.main()