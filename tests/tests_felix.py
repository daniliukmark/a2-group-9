import unittest
from io import StringIO
import sys
from src.vault import handle_del

class TestVaultDelete(unittest.TestCase):
    
    def test_handle_del_ServiceExists_RemovedSuccessfully(self):

        """Should remove the service when it exists and print confirmation."""

        passwords = {"gmail": {"username": "john", "password": "123"}, "github": {"username": "jane", "password": "abc"}}
        parts = ["del", "gmail"]
        
        captured_output = StringIO()
        sys.stdout = captured_output
        handle_del(passwords, parts)
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        self.assertNotIn("gmail", passwords)
        self.assertIn("deleted", output.lower())

    def test_handle_del_ServiceNotFound_PrintsMessage(self):

        """Should print a 'not found' message when the service doesn't exist."""

        passwords = {"github": {"username": "jane", "password": "abc"}}
        parts = ["del", "gmail"]
        captured_output = StringIO()
        sys.stdout = captured_output
        handle_del(passwords, parts)
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        self.assertIn("not found", output.lower())
        self.assertIn("gmail", parts)
        self.assertIn("gmail", output)

    def test_handle_del_MissingArgument_PrintsUsage(self):

        """Should print usage instructions when no service is specified."""

        passwords = {"github": {"username": "jane", "password": "abc"}}
        parts = ["del"]
        captured_output = StringIO()
        sys.stdout = captured_output
        handle_del(passwords, parts)
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        self.assertIn("usage: del", output.lower())

if __name__ == "__main__":
    unittest.main()
