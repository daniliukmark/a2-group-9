import os
import pytest
from unittest.mock import patch, mock_open, MagicMock, call
import json
import base64
import sys

from src import vault


def test_store_roundtrip(tmp_path):
    test_passwords = {"test_service": {"username": "test_user", "password": "test_pass"}}
    master_password = "master123"
    file_path = str(tmp_path / "test_vault.json")
    
    with patch('os.urandom', return_value=b'fixed_salt_12345'):
        mock_file = mock_open()
        with patch('builtins.open', mock_file), \
             patch('os.rename') as mock_rename:
            vault.save_store(file_path, test_passwords, master_password)
            
            written = "".join(call.args[0] for call in mock_file().write.call_args_list)
            file_content = json.loads(written)
            assert "salt" in file_content
            assert "encrypted_data" in file_content
            
            mock_rename.assert_called_with(file_path + ".tmp", file_path)
    
    with patch('builtins.print') as mock_print:
        vault.handle_get(test_passwords, ["get", "test_service"])
        mock_print.assert_any_call("Service:  test_service")
        mock_print.assert_any_call("Username: test_user")
        mock_print.assert_any_call("Password: test_pass")
        
        vault.handle_get(test_passwords, ["get", "nonexistent"])
        mock_print.assert_any_call("Service 'nonexistent' not found.")
        
        vault.handle_get(test_passwords, ["get"])
        mock_print.assert_any_call("Usage: get <service>")
        
        vault.handle_set(test_passwords, ["set", "new_service", "new_user", "new_pass"])
        assert "new_service" in test_passwords
        assert test_passwords["new_service"]["username"] == "new_user"
        assert test_passwords["new_service"]["password"] == "new_pass"
        
        vault.handle_set(test_passwords, ["set", "incomplete"])
        mock_print.assert_any_call("Usage: set <service> <username> <password>")
        
        vault.handle_list(test_passwords)
        mock_print.assert_any_call("Services stored:")
        
        vault.handle_list({})
        mock_print.assert_any_call("No passwords stored yet.")
        
        vault.handle_del(test_passwords, ["del", "test_service"])
        assert "test_service" not in test_passwords
        
        vault.handle_del(test_passwords, ["del", "nonexistent"])
        mock_print.assert_any_call("Service 'nonexistent' not found.")
        
        vault.handle_del(test_passwords, ["del"])
        mock_print.assert_any_call("Usage: del <service>")
        
        vault.print_help()
        mock_print.assert_any_call("\nAvailable commands:")


def test_save_is_atomic(tmp_path):
    file = tmp_path / "v.json"
    test_passwords = {"test": {"username": "user", "password": "pass"}}
    
    vault.save_store(str(file), test_passwords, "master")
    
    assert not (tmp_path / "v.json.tmp").exists()
    
    assert file.exists()
    with open(file) as f:
        data = json.load(f)
        assert "salt" in data
        assert "encrypted_data" in data
    
    with patch('src.vault.inputimeout') as mock_input:
        mock_input.side_effect = [
            "help",
            "list",
            "get test",
            "set new_svc new_user new_pass",
            "del test",
            "unknown_cmd",
            "exit"
        ]
        with patch('builtins.print'):
            result = vault.interactive_session(test_passwords)
            assert "new_svc" in result
            assert "test" not in result
    
    with patch('src.vault.inputimeout', side_effect=vault.TimeoutOccurred()):
        with patch('builtins.print'):
            result = vault.interactive_session(test_passwords)
            assert result == test_passwords


def test_invalid_master_password(tmp_path):
    file = tmp_path / "v.json"
    test_passwords = {"test": {"username": "user", "password": "pass"}}
    
    vault.save_store(str(file), test_passwords, "right_password")
    
    with patch('getpass.getpass', return_value="wrong_password"):
        with pytest.raises(SystemExit) as exc_info:
            vault.load_store(str(file))
        assert exc_info.value.code == 1
    
    with patch('sys.argv', ['vault.py', str(file)]), \
         patch('getpass.getpass', return_value="right_password"), \
         patch('src.vault.load_store', return_value=(test_passwords, "right_password")), \
         patch('src.vault.interactive_session', return_value=test_passwords), \
         patch('src.vault.save_store') as mock_save:
        vault.main()
        mock_save.assert_called_once()
    
    with patch('sys.argv', ['vault.py', str(file)]), \
         patch('getpass.getpass', return_value="right_password"), \
         patch('src.vault.load_store', return_value=(test_passwords, "right_password")), \
         patch('src.vault.interactive_session', side_effect=KeyboardInterrupt()), \
         patch('src.vault.save_store') as mock_save:
        vault.main()
        mock_save.assert_called_once()
    
    with patch('sys.argv', ['vault.py']), \
         patch('builtins.print') as mock_print, \
         pytest.raises(SystemExit) as exc_info:
        vault.main()
        assert exc_info.value.code == 1
        mock_print.assert_any_call("Usage: python vault.py <filepath>")


def test_create_new_store():
    with patch('getpass.getpass', side_effect=["new_password", "new_password"]):
        passwords, master_password = vault.create_new_store()
        assert passwords == {}
        assert master_password == "new_password"
    
    with patch('getpass.getpass', side_effect=["password1", "password2"]):
        with pytest.raises(SystemExit) as exc_info:
            vault.create_new_store()
        assert exc_info.value.code == 1
    
    password = "test_password"
    salt = b"test_salt_12345"
    key = vault.derive_key(password, salt)
    assert isinstance(key, bytes)
    
    non_existent_file = "nonexistent.json"
    with patch('sys.argv', ['vault.py', non_existent_file]), \
         patch('os.path.exists', return_value=False), \
         patch('src.vault.create_new_store', return_value=({}, "new_password")), \
         patch('src.vault.interactive_session', return_value={}), \
         patch('src.vault.save_store') as mock_save:
        vault.main()
        mock_save.assert_called_once()
