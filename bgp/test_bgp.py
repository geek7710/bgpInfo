from unittest.mock import Mock, patch
import bgp

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
        print("=========================")
        print("Starting ciName test if empty")
        print("=========================")
        user_input = VerifyUserInput()
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, False)

    def test_device_name_not_found(self):
        print("\n")
        print("=========================")
        print("Testing ciName not found in BMN")
        print("=========================")
        user_input = VerifyUserInput('wp22-hauppauge')
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user, False)

    def test_device_name_short(self):
        print("\n")
        print("=========================")
        print("Testing ciName short name 'wp-hauppauge'")
        print("=========================")
        user_input = VerifyUserInput('wp-hauppauge')
        from_user = user_input.verify_etc_hosts()
        self.assertEqual(from_user,
                         'wp-hauppauge.gpi.remote.binc.net')

    def test_device_name_long(self):
        print("\n")
        print("=========================")
        print("Testing ciName name FQDN"
              " 'wp-hauppauge.gpi.remote.binc.net'")
        print("=========================")
        user_input = VerifyUserInput(
                        'wp-hauppauge.gpi.remote.binc.net')
        from_etc_hosts = user_input.verify_etc_hosts()
        self.assertEqual(from_etc_hosts, 
                         'wp-hauppauge.gpi.remote.binc.net')


if __name__ == '__main__':
    unittest.main()
