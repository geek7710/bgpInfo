import unittest
from unittest.mock import Mock, patch
from bgp import VerifyUserInput, LoggerClass

class Error(Exception):
    pass

class TestVerifyUserInput(unittest.TestCase):

    def setUp(self):
        self.logger = LoggerClass()
        self.logger.logging()

    @patch('bgp.subprocess.Popen')
    def test_etc_hosts_True(self, mock_subproc):
        reference = VerifyUserInput('some output')
        process_mock = Mock(reference.verify_etc_hosts())
        attrs = {'communicate()[0]': ('some output')}
        process_mock.configure_mock(**attrs)
        mock_subproc.return_value = process_mock
        self.assertTrue(mock_subproc.called)


if __name__ == '__main__':
    unittest.main()
