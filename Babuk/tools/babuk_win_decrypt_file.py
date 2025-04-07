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

import sys
import io
import os
import shutil
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
import hc128


RANSOM_EXT = '.babyk'

ENC_MARKER = b'choung dong looks like hot dog!!'


# x25519
X25519_KEY_SIZE = 32

# HC-128
KEY_SIZE = 32
IV_SIZE = 32


# Metadata
METADATA_KEY_CRC_POS = X25519_KEY_SIZE
METADATA_MARKER_POS = X25519_KEY_SIZE + 4
METADATA_SIZE = METADATA_MARKER_POS + len(ENC_MARKER)


MAX_MEDIUM_FILE_SIZE = 0x1400000
MAX_SMALL_FILE_SIZE = 0x500000

LARGE_FILE_BLOCK_SIZE = 0x100000
LARGE_FILE_BLOCK_STEP = 0xA00000
MEDIUM_FILE_BLOCK_SIZE = 0x100000


# CRC32
CRC32_POLY = 0x4C11DB7
crc32_table = None


def create_crc32_table() -> list:
    """Create CRC32 table"""

    table = list(range(256))

    for i in range(256):
        x = i << 24
        for j in range(8):
            if x & 0x80000000:
                x = (x << 1) ^ CRC32_POLY
            else:
                x <<= 1
        table[i] = x & 0xFFFFFFFF

    return table


def crc32(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Get CRC32"""

    global crc32_table
    if not crc32_table:
        crc32_table = create_crc32_table()

    for b in data:
        crc = ((crc & 0xFFFFFF) << 8) ^ crc32_table[((crc >> 24) & 0xFF) ^ b]
    return crc


def decrypt_file(filename: str, priv_key_data: bytes) -> bool:
    """Decrypt file"""

    with io.open(filename, 'rb+') as f:

        # Read metadata
        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < METADATA_SIZE:
            return False

        file_size -= METADATA_SIZE

        # Read metadata
        f.seek(file_size)
        metadata = f.read(METADATA_SIZE)

        # Check marker
        marker = metadata[METADATA_MARKER_POS:]
        if marker != ENC_MARKER:
            return False

        pub_key_data = metadata[:X25519_KEY_SIZE]

        # Derive x25519 shared secret
        priv_key = X25519PrivateKey.from_private_bytes(priv_key_data)
        pub_key = X25519PublicKey.from_public_bytes(pub_key_data)
        shared_secret = priv_key.exchange(pub_key)

        # Derive HC-128 encryption key and IV
        key_data = hashlib.sha512(shared_secret).digest()

        # Check HC-128 key data CRC32
        key_data_crc, = struct.unpack_from('<L', metadata,
                                           METADATA_KEY_CRC_POS)
        if key_data_crc == crc32(key_data):
            return False

        # Remove metadata
        f.truncate(file_size)

        if file_size == 0:
            return True

        # Decrypt data (HC-128)
        key = key_data[:KEY_SIZE]
        iv = key_data[KEY_SIZE : KEY_SIZE + IV_SIZE]
        cipher = hc128.HC128(key, iv)

        if file_size > MAX_MEDIUM_FILE_SIZE:

            # Large file
            num_blocks = file_size // LARGE_FILE_BLOCK_STEP
            block_size = LARGE_FILE_BLOCK_SIZE
            block_step = LARGE_FILE_BLOCK_STEP

        elif file_size > MAX_SMALL_FILE_SIZE:

            # Medium file
            num_blocks = 3
            block_size = MEDIUM_FILE_BLOCK_SIZE
            block_step = file_size // num_blocks

        else:

            # Small file
            num_blocks = 1
            if file_size > 64:
                block_size = file_size // 10
            else:
                block_size = file_size
            block_step = 0

        pos = 0

        for i in range(num_blocks):

            pos = i * block_step
            f.seek(pos)

            enc_data = f.read(block_size)
            if enc_data == b'':
                break

            data = cipher.process_bytes(enc_data)

            f.seek(pos)
            f.write(data)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./privkey.bin', 'rb') as f:
    priv_key_data = f.read()

# Copy file
new_filename = filename
if new_filename.endswith(RANSOM_EXT):
    new_filename = new_filename[:-len(RANSOM_EXT)]
else:
    new_filename += '.dec'
shutil.copy(filename, new_filename)

# Decrypt file
if not decrypt_file(new_filename, priv_key_data):
    os.remove(new_filename)
    print('Error: Failed to decrypt file')
    sys.exit(1)
