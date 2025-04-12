import streamlit as st
import hashlib
from cryptography.fernet import Fernet


KEY = Fernet.generate_key()
cipher = Fernet(KEY)


stored_data = {} 
failed_attempts = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None


# 🚀 Streamlit Interface
st.set_page_config(page_title="Secure Data System")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Menu", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **store and retrieve data securely** using encryption and passkeys.")

elif choice == "Store Data":
    st.subheader("📦 Store Data")
    text = st.text_area("Enter the text to store:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(text, passkey)  # ✅ passkey added here
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data stored securely!")
            st.code(encrypted, language='text')
        else:
            st.error("❗Please fill both fields.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted = st.text_area("Paste encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted and passkey:
            decrypted = decrypt_data(encrypted, passkey)
            if decrypted:
                st.success(f"🔓 Decrypted: {decrypted}")
            else:
                st.error(f"❌ Wrong passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts! Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("❗Both fields are required.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Access restored. Go back to Retrieve Data.")
        else:
            st.error("❌ Incorrect master password.")
