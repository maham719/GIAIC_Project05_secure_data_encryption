import streamlit as st
import sqlite3 
import hashlib
import os
from cryptography.fernet import Fernet

KEY_FILE="simple_secret.key"
def load_key():
    if not os.path.exists(KEY_FILE):
        key=Fernet.generate_key()
        with open(KEY_FILE,"wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE,"rb") as f:
            key=f.read()
    return key

cipher=Fernet(load_key())

def init_db():
    conn=sqlite3.connect("simple_data.db")
    c=conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
              label TEXT PRIMARY KEY,
              encrypted_text TEXT,
              passkey TEXT)
            ''')
    conn.commit()
    conn.close()

init_db()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

st.title("secure data encrypting and decrypting app")
menu= ["Store Secret","Retrieve Secret"]
choice=st.sidebar.selectbox("Menu",menu)

if choice=="Store Secret":
    st.header("Store Secret")
    label=st.text_input("Enter label (must be unique)")
    secret=st.text_area("Enter secret")
    passkey=st.text_input("Enter passkey",type="password")

    if st.button("Encypt and save"):
        if label and secret and passkey:
            encrypted_text=encrypt(secret)
            hashed_passkey=hash_passkey(passkey)
            
            try:
                conn=sqlite3.connect("simple_data.db")
                c=conn.cursor()
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)",(label, encrypted_text, hashed_passkey))
                conn.commit()
                conn.close()
                st.success("Secret stored successfully!")
            except sqlite3.IntegrityError:
                st.error("Label already exists. Please choose a different label.")
                conn.close()
        else:
            st.error("Please fill in all fields.")
elif choice=="Retrieve Secret":
    st.header("Retrieve Secret")
    label=st.text_input("Enter label")
    passkey=st.text_input("Enter passkey",type="password")

    if st.button("Decrypt"):
       conn=sqlite3.connect("simple_data.db")
       c=conn.cursor()
       c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label,))
       result=c.fetchone()

       if result:
           encrypted_text, stored_hash=result
           if hash_passkey(passkey)==stored_hash:
               decrypted=decrypt(encrypted_text)
               st.success("Decrypted secret:")
               st.code(decrypted)
           else:
               st.error("Invalid passkey.")
       else:
              st.error("Label not found.")