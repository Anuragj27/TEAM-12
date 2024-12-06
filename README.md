# TEAM-12
QR Code Integrity:Hash Encryption And Digital Signatures
import qrcode
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA keys (for signing and verification)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Sign data using private key
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Save keys to files
def save_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Generate QR code
def generate_qr(data, signature):
    qr_data = f"{data}|{signature.hex()}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    img.save("signed_qr.png")
    print("QR code saved as 'signed_qr.png'")
# Main
private_key, public_key = generate_keys()
save_keys(private_key, public_key)

data = "https://secure-site.com"
hashed_data = hashlib.sha256(data.encode()).digest()
signature = sign_data(private_key, hashed_data)
generate_qr(data, signature)








import cv2
from pyzbar.pyzbar import decode
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Load public key
def load_public_key():
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

# Verify signature
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
# Decode QR code
def decode_qr(image_path):
    img = cv2.imread(image_path)
    qr_data = decode(img)
    if qr_data:
        qr_text = qr_data[0].data.decode('utf-8')
        return qr_text
    return None

# Main
public_key = load_public_key()

qr_text = decode_qr("signed_qr.png")
if qr_text:
    data, signature_hex = qr_text.split('|')
    hashed_data = hashlib.sha256(data.encode()).digest()
    signature = bytes.fromhex(signature_hex)

    if verify_signature(public_key, hashed_data, signature):
        print("QR code is valid and untampered.")
    else:
        print("QR code verification failed. Possible tampering detected.")
else:
    print("No QR code detected.")
