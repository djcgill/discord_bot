import base64
import mock
import unittest

from intelix import intelix

from mock import patch

class SessionTests(unittest.TestCase):
    def setUp(self):
        pass

    @patch('intelix.intelix.Client._authenticate')
    def test_init(self, mocked_authenticate):
        client_id = 'test_id'
        client_secret = 'test_secret'
        basic_auth = base64.b64encode(bytes(f"{client_id}:{client_secret}", "utf-8"))
        mocked_authenticate.return_value = None

        intelixobj = intelix.Client(client_id, client_secret)

        self.assertEqual(basic_auth, intelixobj.basic_auth)

        with self.assertRaises(ValueError):
            intelixobj  = intelix.Client(client_id)
       
