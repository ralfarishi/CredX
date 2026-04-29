import unittest
from unittest.mock import MagicMock
import os
import sys

# Ensure credx_v2 can be imported from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from credx_v2.crypto import (
    derive_master_key, 
    derive_auth_key, 
    derive_encryption_key,
    derive_blind_index_key,
    encrypt_aead,
    decrypt_aead,
    secure_wipe,
    generate_salt,
    generate_symmetric_key
)
from credx_v2.vault import VaultManager
from credx_v2.auth import AuthContext

class TestCredX(unittest.TestCase):
    
    def setUp(self):
        self.password = "master-password-123"
        self.salt = generate_salt()
        self.master_key = derive_master_key(self.password, self.salt)
        self.auth_key = derive_auth_key(self.master_key)
        self.encryption_key = derive_encryption_key(self.master_key)
        self.blind_index_key = derive_blind_index_key(self.master_key)
        self.symmetric_key = generate_symmetric_key()
        self.user_id = "test-user-id"

    def test_crypto_flow(self):
        """Test the full encryption/decryption flow."""
        plaintext = "secret data"
        # Test encrypt/decrypt with standard bytes
        ciphertext = encrypt_aead(plaintext, self.encryption_key)
        decrypted = decrypt_aead(ciphertext, self.encryption_key)
        self.assertEqual(plaintext, decrypted)

    def test_bytearray_compatibility(self):
        """Test if crypto functions work with bytearray (Memory Hardening)."""
        plaintext = "secret data"
        mutable_key = bytearray(self.encryption_key)
        
        ciphertext = encrypt_aead(plaintext, mutable_key)
        decrypted = decrypt_aead(ciphertext, mutable_key)
        self.assertEqual(plaintext, decrypted)
        
        # Test wiping
        secure_wipe(mutable_key)
        self.assertEqual(mutable_key, bytearray(len(mutable_key)))

    def test_vault_lazy_decryption(self):
        """Test VaultManager summaries and full entry decryption."""
        mock_supabase = MagicMock()
        
        # Mock data from database (encrypted)
        encrypted_service = encrypt_aead("GitHub", self.symmetric_key)
        encrypted_user = encrypt_aead("user@mail.com", self.symmetric_key)
        encrypted_pass = encrypt_aead("p4ssw0rd", self.symmetric_key)
        
        mock_response = MagicMock()
        mock_response.data = [{
            "id": "entry-1",
            "service_type": encrypted_service,
            "username_email": encrypted_user,
            "encrypted_password": encrypted_pass,
            "created_at": "2024-01-01T00:00:00Z"
        }]
        
        mock_supabase.table().select().eq().neq().order().execute.return_value = mock_response
        
        # Initialize VaultManager with bytearray key and blind index key
        vault = VaultManager(
            mock_supabase, 
            bytearray(self.symmetric_key), 
            bytearray(self.blind_index_key),
            self.user_id
        )
        
        # Test summaries (service and username should be decrypted for selection list)
        summaries = vault.get_entry_summaries()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["service"], "GitHub")
        self.assertEqual(summaries[0]["username"], "user@mail.com")
        
        # Test full entry fetch
        entry = vault.get_full_entry_by_id("entry-1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["service"], "GitHub")
        self.assertEqual(entry["username"], "user@mail.com")
        self.assertEqual(entry["password"], "p4ssw0rd")

    def test_auth_context_wipe(self):
        """Test AuthContext secure wiping."""
        ctx = AuthContext(
            user_id=self.user_id,
            email="test@test.com",
            display_name="Test User",
            symmetric_key=bytearray(self.symmetric_key),
            blind_index_key=bytearray(self.blind_index_key)
        )
        
        original_key = bytes(ctx.symmetric_key)
        ctx.wipe()
        
        # Key should be all zeros now
        self.assertEqual(ctx.symmetric_key, bytearray(len(original_key)))
        self.assertNotEqual(bytes(ctx.symmetric_key), original_key)
        self.assertEqual(ctx.blind_index_key, bytearray(len(self.blind_index_key)))

if __name__ == '__main__':
    unittest.main()
