#!/usr/bin/env python3
"""nip44.py — NIP-44 v2 (Encrypted Payloads) for the nakama protocol.

Implements NIP-44 v2 exactly per https://github.com/nostr-protocol/nips/blob/master/44.md:
  conversation key = HKDF-extract(IKM=shared_x, salt=b'nip44-v2'), shared_x = UNHASHED
  32-byte x coordinate of the ECDH shared point
  message keys   = HKDF-expand(PRK=conversation_key, info=nonce, L=76)
  pad, ChaCha20, HMAC-SHA256(nonce||ciphertext), base64(version||nonce||ct||mac)

Verified against the official test vectors in nips/44.md.
Usage: python nip44.py          (runs self-tests)
"""
import base64
import hashlib
import hmac
import math
import secrets

from coincurve import PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

VERSION = 2
MIN_PLAINTEXT = 1
MAX_PLAINTEXT = 0xFFFFFFFF
EXTENDED_PREFIX_THRESHOLD = 65536


# ---------------------------------------------------------------- HKDF

def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b''
    t = b''
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------- keys

def get_conversation_key(priv_hex: str, pub_hex: str) -> bytes:
    """Long-term conversation key: symmetric under key-role swap."""
    secret = bytes.fromhex(priv_hex)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if not (1 <= int.from_bytes(secret, 'big') < order):
        raise ValueError('invalid private key')
    pub_bytes = bytes.fromhex(pub_hex)
    if len(pub_bytes) == 32:  # x-only (Nostr) -> prepend 0x02 parity byte
        pub_bytes = b'\x02' + pub_bytes
    if len(pub_bytes) != 33 or pub_bytes[0] not in (2, 3):
        raise ValueError('invalid public key')
    shared_x = PublicKey(pub_bytes).multiply(secret).point()[0].to_bytes(32, 'big')
    return hkdf_extract(ikm=shared_x, salt=b'nip44-v2')


def get_message_keys(conversation_key: bytes, nonce: bytes):
    if len(conversation_key) != 32:
        raise ValueError('invalid conversation_key length')
    if len(nonce) != 32:
        raise ValueError('invalid nonce length')
    keys = hkdf_expand(conversation_key, nonce, 76)
    return keys[0:32], keys[32:44], keys[44:76]  # chacha_key, chacha_nonce, hmac_key


# ---------------------------------------------------------------- padding

def calc_padded_len(unpadded_len: int) -> int:
    next_power = 1 << (unpadded_len - 1).bit_length()
    chunk = 32 if next_power <= 256 else next_power // 8
    if unpadded_len <= 32:
        return 32
    return chunk * (math.floor((unpadded_len - 1) / chunk) + 1)


def pad(plaintext: bytes) -> bytes:
    if not (MIN_PLAINTEXT <= len(plaintext) <= MAX_PLAINTEXT):
        raise ValueError('invalid plaintext length')
    if len(plaintext) >= EXTENDED_PREFIX_THRESHOLD:
        prefix = b'\x00\x00' + len(plaintext).to_bytes(4, 'big')
    else:
        prefix = len(plaintext).to_bytes(2, 'big')
    return prefix + plaintext + bytes(calc_padded_len(len(plaintext)) - len(plaintext))


def unpad(padded: bytes) -> bytes:
    first_two = int.from_bytes(padded[0:2], 'big')
    if first_two == 0:
        unpadded_len = int.from_bytes(padded[2:6], 'big')
        if unpadded_len < EXTENDED_PREFIX_THRESHOLD:
            raise ValueError('invalid padding')
        prefix_len = 6
    else:
        unpadded_len = first_two
        prefix_len = 2
    unpadded = padded[prefix_len:prefix_len + unpadded_len]
    if (unpadded_len == 0 or len(unpadded) != unpadded_len
            or len(padded) != prefix_len + calc_padded_len(unpadded_len)):
        raise ValueError('invalid padding')
    return unpadded


# ---------------------------------------------------------------- crypto

def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.ChaCha20(key, b'\x00' * 4 + nonce12), mode=None)
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise ValueError('AAD associated data must be 32 bytes')
    return hmac.new(key, aad + message, hashlib.sha256).digest()


def encrypt(plaintext: str, conversation_key: bytes, nonce: bytes | None = None) -> str:
    if nonce is None:
        nonce = secrets.token_bytes(32)
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = _chacha20(chacha_key, chacha_nonce, padded)
    mac = hmac_aad(hmac_key, ciphertext, nonce)
    return base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode()


def decrypt(payload: str, conversation_key: bytes) -> str:
    if not payload or payload[0] == '#':
        raise ValueError('unknown version')
    if len(payload) < 132:
        raise ValueError('invalid payload size')
    data = base64.b64decode(payload)
    if len(data) < 99:
        raise ValueError('invalid data size')
    if data[0] != VERSION:
        raise ValueError(f'unknown version {data[0]}')
    nonce, ciphertext, mac = data[1:33], data[33:len(data) - 32], data[len(data) - 32:]
    chacha_key, chacha_nonce, hmac_key = get_message_keys(conversation_key, nonce)
    if not hmac.compare_digest(hmac_aad(hmac_key, ciphertext, nonce), mac):
        raise ValueError('invalid MAC')
    return unpad(_chacha20(chacha_key, chacha_nonce, ciphertext)).decode('utf-8')


# ---------------------------------------------------------------- self-tests

def _test_official_vectors():
    # from nips/44.md, "valid.get_conversation_key" / "valid.encrypt_decrypt"
    sec1 = '0000000000000000000000000000000000000000000000000000000000000001'
    sec2 = '0000000000000000000000000000000000000000000000000000000000000002'
    pub2 = PublicKey.from_valid_secret(bytes.fromhex(sec2)).format(compressed=True).hex()
    ck = get_conversation_key(sec1, pub2)
    assert ck.hex() == 'c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d', 'conv key'
    nonce = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000001')
    payload = encrypt('a', ck, nonce)
    assert payload == 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb', 'encrypt'
    assert decrypt(payload, ck) == 'a', 'decrypt'
    # swapped key roles give the same conversation key
    pub1 = PublicKey.from_valid_secret(bytes.fromhex(sec1)).format(compressed=True).hex()
    ck2 = get_conversation_key(sec2, pub1)
    assert ck2 == ck, 'symmetric key'
    assert decrypt(payload, ck2) == 'a', 'decrypt swapped'
    print('ok: official vectors')


def _test_roundtrip_and_tamper():
    from coincurve import PrivateKey
    a = PrivateKey(secrets.token_bytes(32))
    b = PrivateKey(secrets.token_bytes(32))
    ck_a = get_conversation_key(a.secret.hex(), b.public_key.format(compressed=True).hex())
    ck_b = get_conversation_key(b.secret.hex(), a.public_key.format(compressed=True).hex())
    assert ck_a == ck_b
    for msg in ['こんにちは、仲間。', '', 'x' * 1000]:
        if not msg:
            try:
                encrypt(msg, ck_a)
                raise AssertionError('empty plaintext should fail')
            except ValueError:
                continue
        payload = encrypt(msg, ck_a)
        assert decrypt(payload, ck_b) == msg
        # tamper with one base64 char -> must fail
        bad = list(payload)
        bad[40] = 'A' if bad[40] != 'A' else 'B'
        try:
            decrypt(''.join(bad), ck_b)
            raise AssertionError('tampered payload decrypted')
        except ValueError:
            pass
        # wrong key must fail
        c = PrivateKey(secrets.token_bytes(32))
        ck_c = get_conversation_key(c.secret.hex(), a.public_key.format(compressed=True).hex())
        try:
            decrypt(payload, ck_c)
            raise AssertionError('wrong key decrypted')
        except ValueError:
            pass
    print('ok: round-trip, tamper, wrong-key')


def _test_padding_sizes():
    assert calc_padded_len(1) == 32
    assert calc_padded_len(32) == 32
    assert calc_padded_len(33) == 64
    assert calc_padded_len(65535) == 65536
    assert calc_padded_len(65536) == 65536
    assert calc_padded_len(65537) == 81920
    print('ok: padding sizes')


if __name__ == '__main__':
    _test_official_vectors()
    _test_roundtrip_and_tamper()
    _test_padding_sizes()
    print('all nip44 tests passed')
