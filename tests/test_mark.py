import pytest
from unittest.mock import patch, mock_open, call
import json
import io
from contextlib import redirect_stdout

from src import vault


def test_load_store_success(tmp_path):
    file_path = tmp_path / "vault.json"
    original_passwords = {"service1": {"username": "user1", "password": "password1"}}
    master_password = "correct_password"

    vault.save_store(str(file_path), original_passwords, master_password)

    with patch("getpass.getpass", return_value=master_password), patch(
        "builtins.print"
    ):
        loaded_passwords, loaded_master_pw = vault.load_store(str(file_path))

    assert loaded_passwords == original_passwords
    assert loaded_master_pw == master_password


def test_load_store_corrupted_file(tmp_path):
    file_path = tmp_path / "corrupted.json"
    file_path.write_text("this is not valid json")

    with patch("getpass.getpass", return_value="any_password"):
        with pytest.raises(json.JSONDecodeError):
            vault.load_store(str(file_path))


def test_handle_list_sorted_output():
    passwords = {
        "zeta_service": {},
        "alpha_service": {},
        "beta_service": {},
    }
    expected_order = ["alpha_service", "beta_service", "zeta_service"]

    f = io.StringIO()
    with redirect_stdout(f):
        vault.handle_list(passwords)
    output = f.getvalue()

    lines = [line.strip() for line in output.strip().split("\n") if line.strip()]
    services = [line.replace("- ", "") for line in lines if line.startswith("-")]

    assert services == expected_order


def test_interactive_session_unknown_command():
    passwords = {}
    mock_input = ["badcommand", "exit"]

    with patch("src.vault.inputimeout", side_effect=mock_input), patch(
        "builtins.print"
    ) as mock_print:
        vault.interactive_session(passwords)

    mock_print.assert_any_call("Unknown command: 'badcommand'. Type 'help' for a list.")
