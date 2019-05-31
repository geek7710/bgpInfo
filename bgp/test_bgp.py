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
        reference = VerifyUserInput('mbus-cid-rtr1')
        process_mock = Mock(reference.verify_etc_hosts())
        attrs = {'communicate()[0]': ('mbus-cid-rtr1', 'error')}
        process_mock.configure_mock(**attrs)
        mock_subproc.return_value = 'mbus-cid-rtr1.reyes.remote.hms.cdw.com'
        self.assertTrue(mock_subproc.called)


@patch('VerifyUserInput.verify_etc_hosts')
class test_class(mock_verify_etc):

    def test_etc_hosts(self):
        test_class.mock_verify_etc.return_value = 'mbus-cid-rtr1.reyes.remote.hms.cdw.com'
        test_class.mock_verify_etc.assert_called()




if __name__ == '__main__':
    unittest.main()
