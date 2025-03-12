# MIT License
#
# Copyright (c) 2025 Andrey Zhdanov (rivitna)
# https://github.com/rivitna
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Util import Counter


# Kyber1024
KYBER1024_SHAREDKEY_SIZE = 32
KYBER1024_SEED_SIZE = 64
KYBER1024_PUBKEY_SIZE = 1568
KYBER1024_PRIVKEY_SIZE = 3168
KYBER1024_ENC_SIZE = 1568

# AES
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16

# AES GCM
AES_GCM_NONCE_SIZE = 12
AES_GCM_MAC_TAG_SIZE = 16

# AES CTR
AES_CTR_NONCE_SIZE = 16

# Key data
NUM_NONCE1_ENTRIES = 23
NUM_NONCE2_ENTRIES = 32
NONCE1_DATA_SIZE = NUM_NONCE1_ENTRIES * AES_CTR_NONCE_SIZE
NONCE2_DATA_SIZE = NUM_NONCE2_ENTRIES * AES_CTR_NONCE_SIZE
KEYDATA_ENTRY_SIZE = AES_KEY_SIZE + NONCE1_DATA_SIZE


BLOCK_SIZE = 0x80000


MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def rsa_decrypt(enc_data: bytes, priv_key: RSA.RsaKey) -> bytes | None:
    """RSA OAEP decrypt data"""

    decryptor = PKCS1_OAEP.new(priv_key, hashAlgo=SHA512)

    try:
        return decryptor.decrypt(enc_data)
    except ValueError:
        return None


def aes_gcm_decrypt(enc_data: bytes,
                    key: bytes, nonce: bytes) -> bytes | None:
    """AES GCM decrypt data"""

    if len(enc_data) < AES_GCM_MAC_TAG_SIZE:
        return None

    enc_data_size = len(enc_data) - AES_GCM_MAC_TAG_SIZE
    tag = enc_data[enc_data_size:]
    enc_data = enc_data[:enc_data_size]
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    try:
        return cipher.decrypt_and_verify(enc_data, tag)
    except ValueError:
        return None


def aes_ctr_decrypt(enc_data: bytes, key: bytes,
                    nonce: bytes, cnt: int = 0) -> bytes:
    """AES CTR decrypt data"""

    init_val = int.from_bytes(nonce, byteorder='little')
    if cnt != 0:
        init_val = (init_val + cnt) & MASK128
    counter = Counter.new(128, initial_value=init_val, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(enc_data)


def decrypt_block(enc_data: bytes, block_num: int,
                  keydata_entry: bytes, nonce2_data: bytes) -> bytes:
    """Decrypt block data"""

    # Key
    key = keydata_entry[:AES_KEY_SIZE]

    # Nonce
    i1 = block_num % NUM_NONCE1_ENTRIES
    i2 = block_num % NUM_NONCE2_ENTRIES
    n1 = keydata_entry[AES_KEY_SIZE + i1 * AES_CTR_NONCE_SIZE:
                       AES_KEY_SIZE + (i1 + 1) * AES_CTR_NONCE_SIZE]
    n2 = nonce2_data[i2 * AES_CTR_NONCE_SIZE : (i2 + 1) * AES_CTR_NONCE_SIZE]
    nonce = bytearray(n1)
    for i in range(AES_CTR_NONCE_SIZE):
        nonce[i] = (n1[i] + n2[i]) & 0xFF

    # Counter
    cnt = (block_num * BLOCK_SIZE) // AES_BLOCK_SIZE

    # Decrypt (AES CTR)
    return aes_ctr_decrypt(enc_data, key, nonce, cnt)


def get_keydata_entry(keydata: bytes, key_index: int) -> bytes | None:
    """Get key data entry"""

    num_entries = len(keydata) // KEYDATA_ENTRY_SIZE
    if not (0 <= key_index < num_entries):
        return None
    entry_pos = key_index * KEYDATA_ENTRY_SIZE
    return keydata[entry_pos : entry_pos + KEYDATA_ENTRY_SIZE]
