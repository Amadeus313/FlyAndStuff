# fly_vault.py
# pip install cryptography numpy
import os, re, json, time, base64, getpass
from datetime import datetime
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT = "vault"
SIGNAL_FILE = "fly_recording.npy"
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MIN_PW = 8
MAX_TITLE_BYTES = 200

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)

# ---------- fly brain entropy ----------
def load_signal(path=SIGNAL_FILE):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Recording not found: {path}")
    sig = np.asarray(np.load(path, allow_pickle=False)).ravel()
    if np.issubdtype(sig.dtype, np.floating):
        sig = sig[np.isfinite(sig)]
    if sig.size < 4096:
        raise ValueError("Recording too short, need at least 4096 samples")
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
    return np.packbits(bits[: len(bits) // 8 * 8]).tobytes()

# ---------- helpers ----------
def kek_from_password(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))

def user_dir(username):
    return os.path.join(VAULT, username)

def ask_password(prompt, confirm=False):
    """Returns a password, or None if the user presses Enter to cancel."""
    while True:
        pw = getpass.getpass(prompt + f" (min {MIN_PW} chars, Enter to cancel): ")
        if pw == "":
            return None
        if len(pw) < MIN_PW:
            print(f"Too short, use at least {MIN_PW} characters.")
            continue
        if confirm and getpass.getpass("Repeat password: ") != pw:
            print("Passwords do not match.")
            continue
        return pw

def write_private_key(path, priv, password):
    data = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(password.encode("utf-8")))
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)

# ---------- accounts ----------
def register():
    username = input("New username (letters, digits, _ ; 3-32 chars): ").strip().lower()
    if not USERNAME_RE.match(username):
        print("Invalid username.")
        return
    d = user_dir(username)
    if os.path.exists(d):
        print("That username is already taken.")
        return
    pw = ask_password("Account password", confirm=True)
    if pw is None:
        return
    print("Generating RSA-3072 key pair (a few seconds)...")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    os.makedirs(os.path.join(d, "messages"))
    write_private_key(os.path.join(d, "private_key.pem"), priv, pw)
    with open(os.path.join(d, "public_key.pem"), "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Account '{username}' created. You can log in now.")

def login():
    username = input("Username: ").strip().lower()
    pw = getpass.getpass("Account password: ")
    try:
        if not USERNAME_RE.match(username):
            raise ValueError
        with open(os.path.join(user_dir(username), "private_key.pem"), "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=pw.encode("utf-8"))
    except Exception:
        time.sleep(1.5)
        print("Wrong username or password.")
        return None
    print(f"Welcome, {username}.")
    return username, priv

def change_account_password(username, priv):
    new = ask_password("New account password", confirm=True)
    if new is None:
        return
    write_private_key(os.path.join(user_dir(username), "private_key.pem"), priv, new)
    print("Account password changed. Message passwords are unchanged.")

# ---------- messages ----------
def new_message(username, priv):
    pub = priv.public_key()
    title = input("Title: ").strip()
    if not title or len(title.encode("utf-8")) > MAX_TITLE_BYTES:
        print(f"Title is required and must be at most {MAX_TITLE_BYTES} bytes.")
        return
    print("Type your message. Finish with a line containing only END")
    lines = []
    while True:
        line = input()
        if line == "END":
            break
        lines.append(line)
    text = "\n".join(lines)
    if not text.strip():
        print("Empty message, cancelled.")
        return
    pw = ask_password("Password for THIS message", confirm=True)
    if pw is None:
        return

    msg_id = os.urandom(8).hex()
    aad = msg_id.encode()
    data_key = HKDF(hashes.SHA256(), 32, salt=os.urandom(32), info=b"fly-vault-data-key") \
        .derive(brain_entropy() + os.urandom(32))
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, text.encode("utf-8"), aad)

    rsa_wrapped = pub.encrypt(data_key, OAEP)                       # layer 1: account RSA key
    salt, wrap_nonce = os.urandom(16), os.urandom(12)
    wrapped = AESGCM(kek_from_password(pw, salt)).encrypt(wrap_nonce, rsa_wrapped, aad)  # layer 2: message password

    record = {"v": 1, "id": msg_id, "created": datetime.now().isoformat(timespec="seconds"),
              "title_enc": b64e(pub.encrypt(title.encode("utf-8"), OAEP)),
              "salt": b64e(salt), "wrap_nonce": b64e(wrap_nonce), "wrapped": b64e(wrapped),
              "nonce": b64e(nonce), "ct": b64e(ct)}
    path = os.path.join(user_dir(username), "messages", msg_id + ".msg")
    with open(path, "w") as f:
        json.dump(record, f)
    print("Message encrypted and saved.")

def show_list(username, priv):
    folder = os.path.join(user_dir(username), "messages")
    items, skipped = [], 0
    for fn in sorted(os.listdir(folder)):
        if not fn.endswith(".msg"):
            continue
        path = os.path.join(folder, fn)
        try:
            with open(path) as f:
                rec = json.load(f)
            title = priv.decrypt(b64d(rec["title_enc"]), OAEP).decode("utf-8")
            items.append((rec, title, path))
        except Exception:
            skipped += 1
    items.sort(key=lambda x: x[0].get("created", ""))
    if not items:
        print("No messages yet.")
    for i, (rec, title, _) in enumerate(items, 1):
        print(f"{i}) {rec['created'].replace('T', ' ')}  {title}")
    if skipped:
        print(f"({skipped} unreadable file(s) skipped)")
    return items

def pick_message(username, priv):
    items = show_list(username, priv)
    if not items:
        return None
    s = input("Message number (Enter to cancel): ").strip()
    if not s.isdigit() or not 1 <= int(s) <= len(items):
        return None
    return items[int(s) - 1]

def read_message(username, priv):
    picked = pick_message(username, priv)
    if not picked:
        return
    rec, title, _ = picked
    pw = getpass.getpass(f"Password for '{title}': ")
    try:
        aad = rec["id"].encode()
        kek = kek_from_password(pw, b64d(rec["salt"]))
        rsa_wrapped = AESGCM(kek).decrypt(b64d(rec["wrap_nonce"]), b64d(rec["wrapped"]), aad)
        data_key = priv.decrypt(rsa_wrapped, OAEP)
        text = AESGCM(data_key).decrypt(b64d(rec["nonce"]), b64d(rec["ct"]), aad).decode("utf-8")
    except Exception:
        time.sleep(1.5)
        print("Wrong message password, or the file is damaged.")
        return
    print(f"\n----- {title} -----\n{text}\n-------------------")

def delete_message(username, priv):
    picked = pick_message(username, priv)
    if not picked:
        return
    _, title, path = picked
    if input(f"Type DELETE to permanently remove '{title}': ").strip() == "DELETE":
        os.remove(path)
        print("Deleted.")
    else:
        print("Cancelled.")

# ---------- menus ----------
def account_menu(username, priv):
    while True:
        print(f"\n--- {username} ---\n1) New message\n2) List messages\n3) Read a message"
              "\n4) Delete a message\n5) Change account password\n6) Log out")
        c = input("Choose 1-6: ").strip()
        if c == "1":
            new_message(username, priv)
        elif c == "2":
            show_list(username, priv)
        elif c == "3":
            read_message(username, priv)
        elif c == "4":
            delete_message(username, priv)
        elif c == "5":
            change_account_password(username, priv)
        elif c == "6":
            print("Logged out.")
            return

def main():
    os.makedirs(VAULT, exist_ok=True)
    while True:
        print("\n=== Fly Vault ===\n1) Register\n2) Log in\n3) Quit")
        c = input("Choose 1-3: ").strip()
        if c == "1":
            register()
        elif c == "2":
            result = login()
            if result:
                account_menu(*result)
        elif c == "3":
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")