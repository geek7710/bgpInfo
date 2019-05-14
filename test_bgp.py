import unittest
from bgpInfo import LoggerClass, VerifyUserInput

class TestVerifyuser_input(unittest.TestCase):
    """Testing script on gpi-s-bmn03
       It needs BMN to be able to return a valid
       ciName from /etc/hosts file.
    """

    def setUp(self):
        """Initialize Verifyuser_input class"""
        LoggerClass.logging()

    def test_device_input_equal_none(self):
        print("\n")
        print("Starting ciName test if empty")
        user_input = VerifyUserInput()
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, False)

    def test_device_name_not_found(self):
        print("\n")
        print("Testing ciName not found in BMN")
        user_input = VerifyUserInput('wp-nwk-atm01')
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, False)

    def test_device_name_short(self):
        print("\n")
        print("Testing ciName short name 'wp-nwk-atm-xr'")
        user_input = VerifyUserInput('wp-nwk-atm-xr')
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, 'wp-nwk-atm-xr.gpi.remote.binc.net')

    def test_device_name_long(self):
        print("\n")
        print("Testing ciName name FQDN 'wp-nwk-atm-xr.gpi.remote.binc.net'")
        user_input = VerifyUserInput('wp-nwk-atm-xr.gpi.remote.binc.net')
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, 'wp-nwk-atm-xr.gpi.remote.binc.net')


    def test_

if __name__ == '__main__':
    unittest.main()
