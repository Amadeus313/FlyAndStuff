# fly_crypto.py
# pip install cryptography numpy
import os
import getpass
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PRIV, PUB = "private_key.pem", "public_key.pem"
SIGNAL_FILE = "fly_recording.npy"
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

# ---------- fly brain entropy ----------
def load_signal(path=SIGNAL_FILE):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Recording not found: {path}")
    sig = np.load(path, allow_pickle=False)
    sig = np.asarray(sig).ravel()
    if np.issubdtype(sig.dtype, np.floating):
        sig = sig[np.isfinite(sig)]
    if sig.size < 4096:
        raise ValueError(f"Recording too short ({sig.size} samples), need at least 4096")
    if sig.min() == sig.max():
        raise ValueError("Recording is constant, it has no entropy")
    return sig

def brain_entropy():
    sig = load_signal()
    if np.issubdtype(sig.dtype, np.integer):
        bits = (sig & 1).astype(np.uint8)
    else:
        q = np.round((sig - sig.min()) / np.ptp(sig) * 65535).astype(np.uint16)
        bits = (q & 1).astype(np.uint8)
    pairs = bits[: len(bits) // 2 * 2].reshape(-1, 2)
    bits = pairs[pairs[:, 0] != pairs[:, 1], 0]
    if len(bits) < 512:
        raise ValueError("not enough usable entropy in the signal")
    ones = bits.mean()
    print(f"[entropy] {len(bits)} bits kept, ones ratio {ones:.3f}")
    if not 0.45 < ones < 0.55:
        print("[entropy] WARNING: bits look biased, the recording may not be random enough")
    return np.packbits(bits[: len(bits) // 8 * 8]).tobytes()

# ---------- RSA keys ----------
def ensure_keys():
    if os.path.exists(PRIV) and os.path.exists(PUB):
        return
    print("No RSA keys found. Generating an RSA-3072 key pair...")
    pw = getpass.getpass("Password to protect the private key (Enter for none): ")
    enc = (serialization.BestAvailableEncryption(pw.encode())
           if pw else serialization.NoEncryption())
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with open(PRIV, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8, enc))
    with open(PUB, "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Saved {PRIV} (keep secret) and {PUB}.")

def load_private():
    data = open(PRIV, "rb").read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pw = getpass.getpass("Private key password: ")
        return serialization.load_pem_private_key(data, password=pw.encode())

# ---------- encrypt / decrypt ----------
def encrypt_bytes(kind, name, data):
    pub = serialization.load_pem_public_key(open(PUB, "rb").read())
    aes_key = HKDF(hashes.SHA256(), 32, salt=os.urandom(32),
                   info=b"fly-brain-demo").derive(brain_entropy() + os.urandom(32))
    nb = name.encode("utf-8")
    plaintext = bytes([kind]) + len(nb).to_bytes(2, "big") + nb + data
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped = pub.encrypt(aes_key, OAEP)
    return len(wrapped).to_bytes(2, "big") + wrapped + nonce + ciphertext

def decrypt_bytes(blob):
    priv = load_private()
    wl = int.from_bytes(blob[:2], "big")
    wrapped, nonce, ct = blob[2:2 + wl], blob[2 + wl:14 + wl], blob[14 + wl:]
    aes_key = priv.decrypt(wrapped, OAEP)
    pt = AESGCM(aes_key).decrypt(nonce, ct, None)
    kind = pt[0]
    nl = int.from_bytes(pt[1:3], "big")
    return kind, pt[3:3 + nl].decode("utf-8"), pt[3 + nl:]

# ---------- menu ----------
def main():
    ensure_keys()
    print("\n1) Encrypt text\n2) Encrypt a file\n3) Decrypt a .enc file")
    choice = input("Choose 1/2/3: ").strip()

    if choice == "1":
        text = input("Enter text to encrypt: ")
        blob = encrypt_bytes(0, "", text.encode("utf-8"))
        with open("message.enc", "wb") as f:
            f.write(blob)
        print("Encrypted and saved to message.enc")

    elif choice == "2":
        path = input("Path of the file to encrypt: ").strip().strip('"')
        with open(path, "rb") as f:
            data = f.read()
        blob = encrypt_bytes(1, os.path.basename(path), data)
        out = path + ".enc"
        with open(out, "wb") as f:
            f.write(blob)
        print(f"Encrypted and saved to {out}")

    elif choice == "3":
        path = input("Path of the .enc file: ").strip().strip('"')
        with open(path, "rb") as f:
            kind, name, data = decrypt_bytes(f.read())
        if kind == 0:
            print("Decrypted text:", data.decode("utf-8"))
        else:
            out = "decrypted_" + os.path.basename(name)
            with open(out, "wb") as f:
                f.write(data)
            print(f"Decrypted file saved as {out}")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()