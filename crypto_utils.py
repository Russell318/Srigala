"""
crypto_utils.py
================
Semua fungsi kriptografi SRIGALA dikumpulkan di sini, terpisah dari logika
jaringan (network_relay.py) dan tampilan (templates/*.html), supaya mudah
dibaca dan dipelajari satu-persatu.

Pemetaan ke 4 pilar keamanan:
  1. Keamanan (Kerahasiaan) -> AES-256-GCM, kunci sesi diturunkan via ECDH
     (P-256) + HKDF-SHA256. Kunci AES TIDAK PERNAH dikirim lewat jaringan.
  2. Integritas              -> Auth tag bawaan AES-GCM (aes_decrypt akan
     gagal / raise error kalau ciphertext diubah) + pencocokan hash SHA-256.
  3. Autentikasi             -> Tanda tangan ECDSA atas hash file, dibuat
     dengan kunci privat identitas pengirim, diverifikasi dengan kunci
     publik pengirim yang tercatat di direktori server relay.
  4. Non-Repudiasi           -> Tanda tangan ECDSA hanya bisa dibuat oleh
     pemegang kunci privat pengirim -> pengirim tidak bisa menyangkal telah
     mengirim file tersebut.
"""

import os
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

CURVE = ec.SECP256R1()


# -----------------------------------------------------------------------
# Kunci identitas (ECC / ECDSA)
# -----------------------------------------------------------------------

def generate_keypair():
    """Membuat pasangan kunci ECC (P-256) baru. Dipakai untuk identitas
    pengguna maupun untuk kunci ephemeral sekali-pakai per pengiriman file."""
    private_key = ec.generate_private_key(CURVE)
    return private_key, private_key.public_key()


def save_private_key(private_key, path):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, 'wb') as f:
        f.write(pem)


def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_key_to_pem(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode('utf-8')


def public_key_from_pem(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))


def get_or_create_keypair(username: str, keydir: str):
    """Ambil kunci identitas yang sudah ada di disk, atau buat baru kalau
    belum ada (trust-on-first-use, cukup untuk demo/latihan)."""
    os.makedirs(keydir, exist_ok=True)
    priv_path = os.path.join(keydir, f'{username}_private.pem')
    if os.path.exists(priv_path):
        private_key = load_private_key(priv_path)
    else:
        private_key, _ = generate_keypair()
        save_private_key(private_key, priv_path)
    return private_key, private_key.public_key()


def regenerate_keypair(username: str, keydir: str):
    """Sengaja membuat & MENIMPA kunci identitas dengan yang baru.
    Fitur edukasi: bisa dipakai untuk menunjukkan efek 'ganti kunci' ke
    verifikasi file lama (akan gagal identity-check di sisi penerima)."""
    os.makedirs(keydir, exist_ok=True)
    priv_path = os.path.join(keydir, f'{username}_private.pem')
    private_key, public_key = generate_keypair()
    save_private_key(private_key, priv_path)
    return private_key, public_key


# -----------------------------------------------------------------------
# Pilar 1: Kerahasiaan -> ECDH + HKDF-SHA256 (derive kunci sesi) + AES-256-GCM
# -----------------------------------------------------------------------

def derive_aes_key(own_private_key, peer_public_key, info: bytes = b'secure-file-transfer-v1') -> bytes:
    """ECDH: kedua pihak menghitung shared secret yang sama tanpa pernah
    mengirim kunci itu sendiri lewat jaringan. HKDF-SHA256 lalu meregangkan
    shared secret itu menjadi kunci AES 256-bit."""
    shared_secret = own_private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def aes_encrypt(aes_key: bytes, plaintext: bytes, aad: bytes = None):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
    """Kalau ciphertext/nonce/kunci tidak cocok, atau ciphertext diubah
    walau 1 bit, AESGCM akan melempar exception -> ini sekaligus
    memberi Pilar 2 (Integritas) lewat auth tag bawaan GCM."""
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# -----------------------------------------------------------------------
# Pilar 2: Integritas (lapis kedua) -> hash SHA-256 dari isi file asli
# -----------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------
# Pilar 3 & 4: Autentikasi + Non-Repudiasi -> tanda tangan digital ECDSA
# -----------------------------------------------------------------------

def sign_data(private_key, data: bytes) -> bytes:
    """Ditandatangani dengan kunci PRIVAT pengirim -> hanya pengirim yang
    bisa membuat tanda tangan ini (Non-Repudiasi)."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Diverifikasi dengan kunci PUBLIK pengirim -> membuktikan file ini
    benar berasal dari pemilik kunci privat tersebut (Autentikasi)."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# -----------------------------------------------------------------------
# Util encoding
# -----------------------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode('utf-8'))


def fingerprint(pubkey_pem: str) -> str:
    """Sidik jari singkat dari kunci publik (SHA-256, 16 hex pertama),
    supaya mudah dicocokkan mata-ke-mata di GUI tanpa menampilkan PEM utuh."""
    return hashlib.sha256(pubkey_pem.encode('utf-8')).hexdigest()[:16]
