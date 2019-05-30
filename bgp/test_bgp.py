from unittest.mock import mock, patch, TestCase
import bgp

class TestVerifyUserInput(TestCase):

    reference = bgp.VerifyUserInput('ciName')

    @patch(bgp.subprocess)
    @patch(bgp.logging)
    def test_verify_etc_hosts(self, mock_logging, mock_subp):
        mock_logging.info('verify etc/hosts')
        self.assertFalse(mock_subp)