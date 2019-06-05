#!/usr/bin/env python
import unittest
from unittest import mock
import bgp


#class raise_exception(Exception):
#   print("I Crashed!!!")

class test_VerifyUserInput(unittest.TestCase):
    @mock.patch("bgp.subprocess", side_effect=Exception('WHOOPS!'))
    def test_subprocess_fail(self, mock_subprocess):
        print(" ")
        print("Testing bgp.subprocess() Exception")
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (
            '10.255.251.250\tmbus-cid-rtr1.reyes.remote.hms.cdw.com\tmbus-cid-rtr1',
            "error")}
        process_mock.configure_mock(**attrs)
        #mock_subprocess.side_effect = raise_exception
        try:
            proc = mock_subprocess(
                    ['cat', '/etc/hosts'], stdout=mock_subprocess.PIPE)
            stdout = proc.communicate()[0]
            print(stdout)
        except Exception as err:
            print("WHAT HAPPENED? ", err)

    @mock.patch("bgp.subprocess")
    def test_subprocess_good(self, mock_subprocess):
        process_mock = mock.Mock()
        attrs = {'communicate.return_value': (
            '10.255.251.250\tmbus-cid-rtr1.reyes.remote.hms.cdw.com\tmbus-cid-rtr1',
            "error")}
        process_mock.configure_mock(**attrs)
        #mock_subprocess.side_effect = raise_exception
        try:
            proc = mock_subprocess(
                    ['cat', '/etc/hosts'], stdout=mock_subprocess.PIPE)
            stdout = proc.communicate()[0]
            print(stdout)
        except Exception as err:
            print("WHAT HAPPENED? ", err)

    @mock.patch("bgp.VerifyUserInput.verify_etc_hosts", raise_exception=Exception("CRASH!"))
    def test_etc_hosts_error(self, mock_etc_hosts):
        print("testing verify_etc_hosts() Exception")
        output = mock_etc_hosts()

    @mock.patch("bgp.VerifyUserInput.verify_etc_hosts", return_value="mbus-cid-rtr1.reyes.remote.hms.cdw.com")
    def test_etc_hosts_good(self, mock_etc_hosts):
        print("testing verify_etc_hosts() good return")
        output = mock_etc_hosts()
        print(output)



if __name__ == '__main__':
    unittest.main()