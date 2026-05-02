import os
import sys
import uuid
import secrets
from dotenv import load_dotenv
from supabase import create_client

# Add path to import credx from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from credx.auth import (
    get_supabase_client,
    derive_keys_from_password,
    create_user_metadata,
    get_user_metadata,
    AuthContext,
    verify_or_create_canary
)
from credx.crypto import (
    derive_master_key,
    derive_auth_key,
    derive_encryption_key,
    encrypt_aead,
    decrypt_aead,
    generate_salt,
    generate_symmetric_key,
    key_to_hex,
    base64_to_bytes,
    bytes_to_base64
)
from credx.vault import VaultManager

load_dotenv()

def run_integration_test():
    print("🚀 Starting Full-Stack Integration Test...")
    
    # 1. Setup
    try:
        supabase = get_supabase_client()
        print("✅ Supabase connection established.")
    except Exception as e:
        print(f"❌ Failed to connect to Supabase: {e}")
        return

    # Generate unique test user
    test_id = str(uuid.uuid4())[:8]
    test_email = f"test_bot_{test_id}@credx-test.com"
    test_password = f"P@ssw0rd_{test_id}!"
    print(f"📝 Testing with Identity: {test_email}")

    # 2. Simulate Registration Flow (Bypassing UI)
    print("🛠 Simulating Registration...")
    salt = generate_salt()
    symmetric_key = generate_symmetric_key()
    
    master_key = derive_master_key(test_password, salt)
    auth_key = derive_auth_key(master_key)
    encryption_key = derive_encryption_key(master_key)
    
    protected_symmetric_key = encrypt_aead(bytes_to_base64(symmetric_key), encryption_key)
    auth_password = key_to_hex(auth_key)

    try:
        # Supabase Auth Signup
        response = supabase.auth.sign_up({"email": test_email, "password": auth_password})
        if not response.user:
            raise Exception("Signup failed")
        user_id = response.user.id
        
        # Create Metadata
        create_user_metadata(supabase, user_id, test_email, salt, protected_symmetric_key)
        print("✅ Identity registered in Supabase.")
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return

    # 3. Simulate Login Flow
    print("🛠 Simulating Login...")
    metadata = get_user_metadata(supabase, test_email)
    derived_auth_key, derived_enc_key, derived_blind_key = derive_keys_from_password(test_password, metadata)
    
    login_response = supabase.auth.sign_in_with_password({
        "email": test_email, 
        "password": key_to_hex(derived_auth_key)
    })
    
    decrypted_sym_key = base64_to_bytes(decrypt_aead(metadata.protected_symmetric_key, derived_enc_key))
    auth_context = AuthContext(
        user_id=login_response.user.id,
        email=test_email,
        display_name="Test Bot",
        symmetric_key=bytearray(decrypted_sym_key),
        blind_index_key=derived_blind_key
    )
    print("✅ Login successful, Vault key unlocked.")

    # 4. Vault Operations (The "Menu" Tests)
    print("🛠 Testing Vault Operations (Lazy Decryption Flow)...")
    vault = VaultManager(
        supabase, 
        auth_context.symmetric_key, 
        auth_context.blind_index_key,
        auth_context.user_id
    )
    
    # Initialize Canary (Menu 0 internal)
    verify_or_create_canary(supabase, auth_context.symmetric_key, auth_context.user_id)
    
    # Add (Menu 2)
    vault.add_credential("TestService", "bot_user", "bot_pass_123")
    print("✅ Add Credential (Menu 2) passed.")
    
    # List (Menu 1)
    summaries = vault.get_entry_summaries()
    assert any(s["service"] == "TestService" for s in summaries)
    print("✅ List Summaries (Menu 1) passed.")
    
    # Get/Decrypt (Menu 3)
    entry_id = summaries[0]["id"]
    full_entry = vault.get_full_entry_by_id(entry_id)
    assert full_entry["password"] == "bot_pass_123"
    print("✅ Decrypt Payload (Menu 3) passed.")
    
    # Update (Menu 4)
    vault.update_credential(entry_id, "TestService-Updated", "bot_user_v2", "new_password")
    updated_entry = vault.get_full_entry_by_id(entry_id)
    assert updated_entry["service"] == "TestService-Updated"
    assert updated_entry["password"] == "new_password"
    print("✅ Update Node (Menu 4) passed.")
    
    # Delete (Menu 5)
    vault.delete_credential(entry_id, "TestService-Updated")
    final_summaries = vault.get_entry_summaries()
    assert not any(s["id"] == entry_id for s in final_summaries)
    print("✅ Purge Node (Menu 5) passed.")

    # 5. Security Check
    print("🛠 Testing Memory Hardening...")
    auth_context.wipe()
    assert auth_context.symmetric_key == bytearray(32)
    assert auth_context.blind_index_key == bytearray(32)
    print("✅ Memory Wiping passed.")

    print("\n🎉 ALL TESTS PASSED! The application architecture is verified and stable.")
    print(f"Cleanup: User {test_email} remains in database for audit.")

if __name__ == "__main__":
    run_integration_test()
