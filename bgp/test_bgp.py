#!/usr/bin/env python
import unittest
from unittest import mock
import bgp


class TestVerifyUserInput(unittest.TestCase):

    def setUp(self):
        self.logger = bgp.LoggerClass()
        self.logger.logging()

    @mock.patch("bgp.VerifyUserInput")
    def test_verify_user_input_class(self, mock_verify_user_class):
        mock_instance = mock_verify_user_class('mbus-cid-rtr1')
        mock_instance.return_value.verify_etc_hosts.return_value = 'mbus-cid-rtr1.reyes.remote.hms.cdw.com'
        process_mock = mock_instance.verify_etc_hosts()
        mock_instance.return_value.filter_findstring_output.return_value = 'mbus-cid-rtr1.reyes.remote.hms.cdw.com'
        output = mock_instance.filter_findstring_output()
        mock_instance.return_value.verify_multiple_entries.return_value = 'mbus-cid-rtr1.reyes.remote.hms.cdw.com'
        output = mock_instance.verify_multiple_entries()
        print(output)


if __name__ == '__main__':
    unittest.main()
