import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()

if 'page' not in st.session_state:
    st.session_state.page = 'Home'

cipher = Fernet(st.session_state.KEY)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(enc_text, passkey):
    hashed = hash_passkey(passkey)
    data = st.session_state.stored_data.get(enc_text)
    if data and data['passkey'] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(enc_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Navigation
if st.session_state.failed_attempts >= 3:
    st.session_state.page = 'Login'

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))

# Sync session page with sidebar choice, except forced login page
if st.session_state.page != 'Login' and choice != st.session_state.page:
    st.session_state.page = choice

# Pages
if st.session_state.page == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif st.session_state.page == "Store Data":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.write("Save the following encrypted text to retrieve it later:")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

elif st.session_state.page == "Retrieve Data":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.page = 'Login'
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif st.session_state.page == "Login":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded demo password
            st.session_state.failed_attempts = 0
            st.session_state.page = "Retrieve Data"
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")
