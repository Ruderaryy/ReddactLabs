from cryptography.fernet import Fernet

#new, unique key
key = Fernet.generate_key()

with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("Successfully generated and saved a new secret key to 'secret.key'.")

import sys
import json
from cryptography.fernet import Fernet

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("ERROR: secret.key not found. Please generate key first.")
        sys.exit(1)

def load_redaction_db():
    try:
        with open("redaction_db.json", 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("ERROR: redaction_db.json not found. No reversible redactions have been made yet.")
        sys.exit(1)


def unredact_value(redaction_id):
    key = load_key()
    f_cipher = Fernet(key)
    db = load_redaction_db()
        
    if redaction_id in db:
        encrypted_data = db[redaction_id]["data"].encode()
        try:
            decrypted_data = f_cipher.decrypt(encrypted_data).decode()
            pii_type = db[redaction_id]["type"]
            print("\n----------- Redaction Details ----------")
            print(f"  ID:           {redaction_id}")
            print(f"  Type:         {pii_type}")
            print(f"  Original Value: {decrypted_data}")
            print("-------------------------\n")
        except Exception as e:
            print(f"ERROR: Failed to decrypt data. The secret key may have changed. Error: {e}")
    else:
        print(f"ERROR: Redaction ID '{redaction_id}' not found in the database.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("This tool allows you to look up the original value of a reversible redaction.")
        print("\nUsage: python unredact.py <redaction_id>")
        print("Example: python unredact.py [REDACT-f81d4fae-7dec-11d0-a765-00a0c91e6bf6]")
        sys.exit(1)
    
    the_id_to_find = sys.argv[1]
    unredact_value(the_id_to_find)