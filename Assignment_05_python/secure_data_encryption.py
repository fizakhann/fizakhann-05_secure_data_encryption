
import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Key generation for encryption (note: store safely in real apps)
encryption_key = Fernet.generate_key()
secure_cipher = Fernet(encryption_key)

# In-memory storage structures
user_records = {}       # Format: {"username": {"cipher_text": ..., "key_hash": ...}}
login_attempts = {}     # Format: {"username": attempt_count}

# Hashing function for passkeys
def create_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encrypt plain text
def encode_message(message):
    return secure_cipher.encrypt(message.encode()).decode()

# Attempt decryption with passkey
def decode_message(username, cipher_text, password):
    if username not in user_records:
        return None

    if username not in login_attempts:
        login_attempts[username] = 0

    hashed_input = create_hash(password)
    entry = user_records[username]

    if entry["cipher_text"] == cipher_text and entry["key_hash"] == hashed_input:
        login_attempts[username] = 0
        return secure_cipher.decrypt(cipher_text.encode()).decode()
    else:
        login_attempts[username] += 1
        return None

# Streamlit Interface
st.title("🛡️ Personal Data Vault")

# Sidebar Navigation
nav = st.sidebar.selectbox("Go to", ["Dashboard", "Save Info", "Access Info", "Reauthorize"])

if nav == "Dashboard":
    st.header("📘 Welcome to Your Secure Vault")
    st.markdown("Save and retrieve sensitive notes using a secret key. No external database involved.")

elif nav == "Save Info":
    st.header("📝 Encrypt and Save")
    username = st.text_input("Choose a username:")
    plain_text = st.text_area("Type your secret note here:")
    secret_key = st.text_input("Set a passkey for this entry:", type="password")

    if st.button("Secure & Save"):
        if username and plain_text and secret_key:
            key_hash = create_hash(secret_key)
            encrypted_note = encode_message(plain_text)
            user_records[username] = {"cipher_text": encrypted_note, "key_hash": key_hash}
            st.success("🧾 Your information is now encrypted and saved securely.")
        else:
            st.warning("⚠️ Please fill all fields before saving.")

elif nav == "Access Info":
    st.header("🔓 Retrieve Your Note")
    username = st.text_input("Your Username:")
    encrypted_input = st.text_area("Paste your encrypted note here:")
    input_key = st.text_input("Enter your passkey:", type="password")

    if st.button("Unlock Note"):
        if username and encrypted_input and input_key:
            result = decode_message(username, encrypted_input, input_key)
            attempts_left = 3 - login_attempts.get(username, 0)

            if result:
                st.success(f"📄 Decrypted Note: {result}")
            else:
                st.error(f"❌ Wrong key! Attempts remaining: {attempts_left}")
                if attempts_left <= 0:
                    st.warning("🔐 Maximum attempts reached! Redirecting for reauthorization.")
                    st.experimental_rerun()
        else:
            st.info("🔍 All fields are needed for decryption.")

elif nav == "Reauthorize":
    st.header("🔐 Reauthorization Required")
    admin_pass = st.text_input("Master Access Key:", type="password")

    if st.button("Re-Login"):
        if admin_pass == "myadmin321":  # Customized password
            login_attempts.clear()
            st.success("✅ Access restored. You can try retrieving data again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
