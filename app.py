import streamlit as st
from PIL import Image
import numpy as np
import csv
import os
import qrcode
import io
import base64
import time

# ------------------ Core Encryption/Decryption Functions ------------------
def generate_binary_key(length):
    """Generate random binary key of specified bit length"""
    return ''.join(np.random.choice(['0', '1'], size=length))

def encrypt_message(message, binary_key):
    key_bytes = [int(binary_key[i:i+8], 2) for i in range(0, len(binary_key), 8)]
    message_bytes = message.encode('utf-8')
    
    # Extend key to match message length
    extended_key = np.array([key_bytes[i % len(key_bytes)] for i in range(len(message_bytes))], dtype=np.uint8)
    encrypted_bytes = bytearray(x ^ k for x, k in zip(message_bytes, extended_key))
    return base64.b64encode(encrypted_bytes).decode('ascii')

def decrypt_message(encrypted_message, binary_key):
    try:
        key_bytes = [int(binary_key[i:i+8], 2) for i in range(0, len(binary_key), 8)]
        encrypted_bytes = base64.b64decode(encrypted_message)
        
        # Extend key to match message length
        extended_key = np.array([key_bytes[i % len(key_bytes)] for i in range(len(encrypted_bytes))], dtype=np.uint8)
        decrypted_bytes = bytearray(x ^ k for x, k in zip(encrypted_bytes, extended_key))
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

def encrypt_image(image, binary_key):
    key_bytes = [int(binary_key[i:i+8], 2) for i in range(0, len(binary_key), 8)]
    image_array = np.array(image)
    original_shape = image_array.shape
    original_dtype = image_array.dtype
    flattened = image_array.flatten()
    
    # Extend key to match image data length
    extended_key = np.tile(key_bytes, (flattened.size // len(key_bytes)) + 1)[:flattened.size]
    encrypted_data = np.bitwise_xor(flattened, extended_key)
    return {'data': encrypted_data, 'shape': original_shape, 'dtype': str(original_dtype)}

def decrypt_image(encrypted_data, binary_key):
    key_bytes = [int(binary_key[i:i+8], 2) for i in range(0, len(binary_key), 8)]
    data = encrypted_data['data']
    original_shape = tuple(encrypted_data['shape'])
    original_dtype = np.dtype(encrypted_data['dtype'])
    
    # Extend key to match image data length
    extended_key = np.tile(key_bytes, (data.size // len(key_bytes)) + 1)[:data.size]
    decrypted_flat = np.bitwise_xor(data, extended_key)
    return decrypted_flat.reshape(original_shape).astype(original_dtype)

# ------------------ UI Enhancements ------------------
def copy_confirmation():
    st.markdown("""
    <style>
    .copy-confirm {
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 10px;
        background: #2e7d32;
        color: black;
        border-radius: 4px;
        display: none;
    }
    </style>
    <script>
    document.addEventListener('copy', function(e) {
        const copyConfirm = document.createElement('div');
        copyConfirm.className = 'copy-confirm';
        copyConfirm.textContent = '✓ Copied!';
        document.body.appendChild(copyConfirm);
        setTimeout(() => copyConfirm.remove(), 2000);
    });
    </script>
    """, unsafe_allow_html=True)

def show_copyable(text, label=None):
    if label:
        st.markdown(f"**{label}**")
    st.markdown(f"""
    <div style="padding: 15px; border: 2px solid #1b5e20; border-radius: 5px; 
                background-color: #2e7d32; color: white; font-family: monospace;
                word-break: break-word; cursor: pointer;" onclick="navigator.clipboard.writeText(`{text}`)">
        {text}
        <div style="text-align: right; font-size: 12px; color: white;">Click to copy</div>
    </div>
    """, unsafe_allow_html=True)


# ------------------ Updated Text Interface ------------------
def text_interface():
    st.header("📝 Text Encryption")
    col1, col2 = st.columns(2, gap="medium")

    with col1:
        with st.container():
            st.subheader("Encrypt")
            message = st.text_area("Enter message:", height=120)
            
            if st.button("🔒 Encrypt Message"):
                if message:
                    # Generate binary key with minimum 256 bits (32 bytes)
                    key_length = max(256, len(message)*8)
                    binary_key = generate_binary_key(key_length)
                    
                    encrypted = encrypt_message(message, binary_key)
                    st.session_state.encrypted_text = encrypted
                    st.session_state.binary_key = binary_key
                else:
                    st.error("Please enter a message")

            if 'encrypted_text' in st.session_state:
                st.markdown("---")
                st.subheader("Encrypted Data")
                show_copyable(st.session_state.encrypted_text, "Encrypted Message")
                
                st.subheader("Encryption Key")
                show_copyable(st.session_state.binary_key, "Binary Key")
                
                # QR Code Generation
                qr = qrcode.QRCode(
                    version=1,
                    box_size=6,
                    border=4,
                    error_correction=qrcode.constants.ERROR_CORRECT_L
                )
                qr.add_data(st.session_state.binary_key)
                img = qr.make_image(fill_color="#302b63", back_color="#ffffff")
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                buffered.seek(0)
                st.image(buffered, width=200)

    with col2:
        with st.container():
            st.subheader("Decrypt")
            encrypted_input = st.text_area("Enter encrypted message:", height=100)
            key_input = st.text_input("Enter decryption key (binary string):")
            
            if st.button("🔓 Decrypt Message"):
                if encrypted_input and key_input:
                    try:
                        # Validate binary key
                        if not all(c in '01' for c in key_input):
                            raise ValueError("Invalid binary characters")
                        if len(key_input) % 8 != 0:
                            raise ValueError("Key length must be multiple of 8")
                            
                        decrypted_message = decrypt_message(encrypted_input.strip(), key_input)
                        if decrypted_message:
                            st.success(f"Decrypted Message:\n{decrypted_message}")
                        else:
                            st.error("Decryption failed!")
                    except ValueError as ve:
                        st.error(f"Invalid key: {str(ve)}")
                    except Exception as e:
                        st.error(f"Error during decryption: {str(e)}")

# ------------------ Updated Image Interface ------------------
def image_interface():
    st.header("🖼️ Image Encryption")
    tab1, tab2 = st.tabs([" Encrypt ", " Decrypt "])

    with tab1:
        uploaded_file = st.file_uploader("Choose an image:", type=["png", "jpg", "jpeg"])
        if uploaded_file:
            cols = st.columns(2)
            with cols[0]:
                image = Image.open(uploaded_file)
                if "original_image" not in st.session_state:
                    st.session_state.original_image = image.copy()
                resized_image = image.resize((300, 300))
                st.image(resized_image, caption="Original Image", width=300)

            if st.button("🔒 Encrypt Image"):
                # Generate 2048-bit binary key for images
                binary_key = generate_binary_key(2048)
                encrypted = encrypt_image(resized_image.convert('RGB'), binary_key)
                st.session_state.encrypted_img = encrypted
                st.session_state.img_binary_key = binary_key

            if 'encrypted_img' in st.session_state:
                with cols[1]:
                    st.image(np.random.randint(0, 256, size=(300,300,3), dtype=np.uint8),
                            caption="Encrypted Preview", width=300)
                st.markdown("---")
                show_copyable(st.session_state.img_binary_key, "Image Encryption Key")

    with tab2:
        if 'encrypted_img' in st.session_state:
            key_input = st.text_input("Enter image decryption key (binary string):")
            if st.button("🔓 Decrypt Image"):
                if key_input:
                    try:
                        # Validate binary key
                        if not all(c in '01' for c in key_input):
                            raise ValueError("Invalid binary characters")
                        if len(key_input) % 8 != 0:
                            raise ValueError("Key length must be multiple of 8")
                            
                        decrypted = decrypt_image(st.session_state.encrypted_img, key_input)
                        cols = st.columns(2)
                        with cols[0]:
                            st.image(decrypted, caption="Decrypted Image", width=300)
                        with cols[1]:
                            if "original_image" in st.session_state:
                                original = st.session_state.original_image
                                resized_original = original.resize((300, 300))
                                st.image(resized_original, caption="Original Image", width=300)
                    except Exception as e:
                        st.error(f"Decryption failed: {str(e)}")
                else:
                    st.error("Please enter decryption key")

# ------------------ Main Application ------------------
def main():
    st.set_page_config(
        page_title="Secure Crypto App",
        page_icon="🔐",
        layout="centered"
    )
    copy_confirmation()
    
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        auth_interface()
    else:
        st.sidebar.title("Navigation")
        nav = st.sidebar.radio("", ["Text", "Image", "About"], horizontal=True)
        
        if st.sidebar.button("🚪 Logout"):
            st.session_state.clear()
            st.rerun()

        if nav == "Text":
            text_interface()
        elif nav == "Image":
            image_interface()
        else:
            st.header("About")
            st.markdown("""
            ### Enhanced Security Features:
            - 256-bit minimum binary key encryption
            - XOR-based cryptographic operations
            - Secure binary key management
            - Copy protection with confirmation
            - Cross-platform compatibility
            """)

# ------------------ User Authentication ------------------
def auth_interface():
    col1, col2 = st.columns([1, 2])
    with col1:
        st.image("https://cdn-icons-png.flaticon.com/512/1067/1067555.png", width=120)
    with col2:
        st.markdown("## Secure Encryption Suite")
    
    with st.expander("🔐 Login/Register", expanded=True):
        tab1, tab2 = st.tabs([" Login ", " Register "])
        with tab1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if login_user(username, password):
                    st.session_state.logged_in = True
                    st.rerun()
        with tab2:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            if st.button("Create Account"):
                register_user(new_user, new_pass)

# ------------------ User Management ------------------
def register_user(username, password):
    if not os.path.exists("users.csv"):
        with open("users.csv", "w") as f:
            f.write("username,password\n")
    with open("users.csv", "r") as f:
        if username in [line.split(',')[0] for line in f.readlines()]:
            st.error("Username already exists!")
            return False
    with open("users.csv", "a") as f:
        f.write(f"{username},{password}\n")
    return True

def login_user(username, password):
    if not os.path.exists("users.csv"):
        return False
    with open("users.csv", "r") as f:
        for line in f.readlines()[1:]:
            if line.startswith(f"{username},{password}"):
                return True
    return False

if __name__ == "__main__":
    main()
