import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
                                            #? DATA STORAGE
DATA_FILE = "secure_data.json"

def load_data_from_file():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data_to_file(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

                                            #? DATA STORAGE

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data =  load_data_from_file()

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

if st.session_state.failed_attempts >= 3:
    st.session_state.page = 'Login'

st.title("🔒 Secure Data Encryption System")
tab1, tab2, tab3 ,tab4= st.tabs(["Store Data", "Retrieve Data", "Login",'Developer Tools'])
#* Store Data Tab 
with tab1:
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data_to_file(st.session_state.stored_data)

            st.success("✅ Data stored securely!")
            st.write("Save the following encrypted text to retrieve it later:")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

if st.session_state.page != "Login":
    with tab2:
        st.subheader("🔍 Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)

                if decrypted_text:
                    st.success(f"✅ Decrypted Data:↲")
                    st.code(decrypted_text)
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state.page = 'Login'
                        st.rerun()
            else:
                st.error("⚠️ Both fields are required!")
else:
    st.warning("🔒 Please login to retrieve your data.")
if st.session_state.page == "Login":
    with tab3:
        st.subheader("🔑 Reauthorization Required")
        login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")

        if st.button("Login"):
            if login_pass == "admin123":  # Hardcoded demo password
                st.session_state.failed_attempts = 0
                st.session_state.page = "Retrieve Data"
                st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
                st.rerun()
            else:
                st.error("❌ Incorrect password!")
else:
    with tab3:
        st.subheader("🔑 You are logged in!")
        st.write("You can now store and retrieve your data securely.")
with tab4:
    with st.expander("🔍 Debug: Show Stored Data"):
        st.json(st.session_state.stored_data)
    if st.button("Delete Stored Data File"):
        if os.path.exists(DATA_FILE):
            os.remove(DATA_FILE)
        st.session_state.stored_data = {}
        st.success("✅ Stored data file deleted!")
