import io
from contextlib import redirect_stdout
from unittest.mock import patch

from src.vault import create_new_store
from src.vault import print_help

def test_create_new_store_success():

    with patch("getpass.getpass", side_effect=["lalala123", "lalala123"]):
        f = io.StringIO()

        with redirect_stdout(f):
            store, password = create_new_store()

    out = f.getvalue()

    assert "NO current vault, creating new one...." in out
    assert "New vault created" in out
    assert store == {}
    assert password == "lalala123"

def test_create_new_store_password_mismatch(): #same test as inital test/test1, but chekcs for correctness when confirmed password does not match initial pw.

    with patch("getpass.getpass", side_effect=["pass1", "pass2"]), \
        patch("sys.exit") as mock_exit:
        f = io.StringIO()

        with redirect_stdout(f):
            create_new_store()

    out = f.getvalue()

    assert "You entered a different confirmation password" in out

    mock_exit.assert_called_once_with(1)

def test_print_help_output(): #adds test for print (pretty useless i'd say, but does increase coverage)
    
    expected_output = """
Available commands:
  get <service>              - Get password for a service
  set <service> <user> <pass>- Add/update a password
  del <service>              - Delete a password
  list                       - List all services
  help                       - Show this help message
  exit                       - Save and exit the vault
"""

    f = io.StringIO()

    with redirect_stdout(f):
        print_help()
    
    out = f.getvalue()
    assert out.strip() == expected_output.strip()


