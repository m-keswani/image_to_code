import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Function to process image
def process_image(image_data):
    try:
        # Convert the image to a hash code (SHA-256)
        hash_code = hashlib.sha256(image_data).hexdigest()
        st.write("Hash Code:", hash_code)

        # Encrypt the hash code
        encrypted_code = cipher.encrypt(hash_code.encode())
        st.write("Encrypted Code:", encrypted_code.decode())

        # Display key for decryption
        st.write("Encryption Key (store this securely!):", key.decode())

    except Exception as e:
        st.error(f"Error processing image: {e}")

# Streamlit UI
st.title("Digital Forensic Tool: Image to Code Conversion")

# Allow the user to upload an image file
uploaded_image = st.file_uploader("Upload an image file", type=["png", "jpg", "jpeg"])

if st.button("Convert Image"):
    if uploaded_image is not None:
        process_image(uploaded_image.read())
    else:
        st.warning("Please upload an image file.")
