import streamlit as st
import hashlib
import time
import uuid
import base64
from cryptography.fernet import Fernet

# Session State Initialization
if 'wrong_attempts' not in st.session_state:
    st.session_state.wrong_attempts = 0
if 'saved_records' not in st.session_state:
    st.session_state.saved_records = {}
if 'current_screen' not in st.session_state:
    st.session_state.current_screen = "Home"
if 'last_wrong_time' not in st.session_state:
    st.session_state.last_wrong_time = 0

# Helper Functions


def create_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_key(password):
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])


def encrypt_message(message, password):
    key = create_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).decode()


def decrypt_message(cipher_text, password, record_id):
    try:
        password_hash = create_hash(password)
        if record_id in st.session_state.saved_records and st.session_state.saved_records[record_id]["password_hash"] == password_hash:
            key = create_key(password)
            cipher = Fernet(key)
            decrypted_text = cipher.decrypt(cipher_text.encode()).decode()
            st.session_state.wrong_attempts = 0
            return decrypted_text
        else:
            st.session_state.wrong_attempts += 1
            st.session_state.last_wrong_time = time.time()
            return None
    except:
        st.session_state.wrong_attempts += 1
        st.session_state.last_wrong_time = time.time()
        return None


def new_record_id():
    return str(uuid.uuid4())


def reset_attempts():
    st.session_state.wrong_attempts = 0


def switch_screen(screen):
    st.session_state.current_screen = screen


# App UI
st.title("🔐 Secure Data Vault")

# Sidebar Navigation
pages = ["Home", "Save Data", "Retrieve Data", "Login"]
selection = st.sidebar.selectbox(
    "Navigate", pages, index=pages.index(st.session_state.current_screen))
st.session_state.current_screen = selection

# Lockout Check
if st.session_state.wrong_attempts >= 3:
    st.session_state.current_screen = "Login"

# Screens
if st.session_state.current_screen == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Store and retrieve your data safely with password encryption.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Save Data", use_container_width=True):
            switch_screen("Save Data")
    with col2:
        if st.button("🔍 Retrieve Data", use_container_width=True):
            switch_screen("Retrieve Data")

    st.info(
        f"Currently, you have {len(st.session_state.saved_records)} records saved.")

elif st.session_state.current_screen == "Save Data":
    st.subheader("➕ Save Your Data")
    data = st.text_area("Enter your text:")
    password = st.text_input("Set a Password:", type="password")
    confirm_password = st.text_input("Confirm Password:", type="password")

    if st.button("Encrypt & Save"):
        if data and password and confirm_password:
            if password != confirm_password:
                st.error("⚠️ Passwords do not match!")
            else:
                record_id = new_record_id()
                password_hash = create_hash(password)
                encrypted_data = encrypt_message(data, password)

                st.session_state.saved_records[record_id] = {
                    "encrypted_data": encrypted_data,
                    "password_hash": password_hash
                }

                st.success("✅ Data saved securely!")
                st.code(record_id, language="text")
                st.info("Save this Record ID for future retrieval.")
        else:
            st.error("⚠️ Please fill all fields.")

elif st.session_state.current_screen == "Retrieve Data":
    st.subheader("🔍 Retrieve Saved Data")

    remaining = 3 - st.session_state.wrong_attempts
    st.info(f"Attempts remaining: {remaining}")

    record_id = st.text_input("Enter Record ID:")
    password = st.text_input("Enter Password:", type="password")

    if st.button("Decrypt"):
        if record_id and password:
            if record_id in st.session_state.saved_records:
                cipher_text = st.session_state.saved_records[record_id]["encrypted_data"]
                decrypted = decrypt_message(cipher_text, password, record_id)

                if decrypted:
                    st.success("✅ Successfully Decrypted!")
                    st.markdown("### Your Data:")
                    st.code(decrypted, language="text")
                else:
                    st.error(
                        f"❌ Wrong password! Attempts left: {3 - st.session_state.wrong_attempts}")
            else:
                st.error("❌ Record ID not found!")

            if st.session_state.wrong_attempts >= 3:
                st.warning("🚨 Too many wrong attempts. Redirecting to Login.")
                st.session_state.current_screen = "Login"
                st.rerun()
        else:
            st.error("⚠️ Both fields are mandatory.")

elif st.session_state.current_screen == "Login":
    st.subheader("🔑 Login Required")

    if time.time() - st.session_state.last_wrong_time < 10 and st.session_state.wrong_attempts >= 3:
        wait_time = int(10 - (time.time() - st.session_state.last_wrong_time))
        st.warning(f"🕒 Please wait {wait_time} seconds before retrying.")

        # Auto-refresh after 1 second
        time.sleep(1)
        st.rerun()

    else:

        st.markdown("🔐 **Hint**: The password is `admin123`")

        master_pass = st.text_input("Master Password:", type="password")

        if st.button("Login"):
            if master_pass == "admin123":
                reset_attempts()
                st.success("✅ Logged in successfully!")
                st.session_state.current_screen = "Home"
                st.rerun()
            else:
                st.error("❌ Wrong master password!")