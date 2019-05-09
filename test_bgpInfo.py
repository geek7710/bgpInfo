import unittest
import bgpInfo

class TestVerifyUserInput(unittest.TestCase):
    """Testing script on gpi-s-bmn03
       It needs BMN to be able to return a valid
       ciName from /etc/hosts file.
    """

    @classmethod
    def setUpClass(cls):
        """Initialize VerifyUserInput class"""
        LoggerClass.logging()

    def test_ciNameEqualNone(self):
        print("Starting ciName test if empty")
        userInput = VerifyUserInput()
        fromUser = userInput.verifyEtcHost()
        self.assertEqual(fromUser, False)

    def test_ciNameNotFound(self):
        print("Testing ciName not found in BMN")
        userInput = VerifyUserInput('wp-nwk-atm01')
        fromUser = userInput.verifyEtcHost()
        self.assertEqual(fromUser, False)

    def test_ciNameShort(self):
        print("Testing ciName short name 'wp-nwk-atm-xr'")
        userInput = VerifyUserInput('wp-nwk-atm-xr')
        fromUser = userInput.verifyEtcHost()
        self.assertEqual(fromUser, 'wp-nwk-atm-xr.gpi.remote.binc.net')

    def test_ciNameLong(self):
        print("Testing ciName short name 'wp-nwk-atm-xr.gpi.remote.binc.net'")
        userInput = VerifyUserInput('wp-nwk-atm-xr.gpi.remote.binc.net')
        fromUser = userInput.verifyEtcHost()
        self.assertEqual(fromUser, 'wp-nwk-atm-xr.gpi.remote.binc.net')


if __name__ == '__main__':
    unittest.main()
