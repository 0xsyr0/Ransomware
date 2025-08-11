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
import os
import io
import hashlib
import binascii


UUID_TEMPLATE = b'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'
UUID_CHARS = b'ABCDEF0123456789'

MUTEX_NAME_CHARS = b'WhosYourBunny'


def get_file_sha256(filename: str) -> bytes:
    """Get the file contents SHA-256 hash"""

    with io.open(filename, 'rb') as f:
        file_data = f.read()

    h = hashlib.sha256(file_data)
    return h.digest()


def get_rnd_seed(digest: bytes) -> int:
    """Get rand seed from digest"""

    seed = 0
    for i, b in enumerate(digest):
        if i & 1 == 0:
            b >>= 1
        seed = (seed + b) & 0xFFFFFFFF

    return seed


def rand(seed: int) -> (int, int):
    """Generates a pseudorandom number (rand)"""

    seed = (seed * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return ((seed >> 16) & 0x7FFF), seed


def make_uuid_str(digest: bytes) -> str:
    """Make UUID string from digest"""

    # Get rand seed from digest
    seed = get_rnd_seed(digest)

    uuid = bytearray(UUID_TEMPLATE)
    for i in range(len(uuid)):
        if uuid[i] == ord('X'):
            n, seed = rand(seed)
            uuid[i] = UUID_CHARS[n % len(UUID_CHARS)]

    return uuid.decode()


def make_mutex_name(digest: bytes) -> str:
    """Make mutex name from digest"""

    # Get rand seed from digest
    seed = get_rnd_seed(digest)

    mutex_name = bytearray(MUTEX_NAME_CHARS)
    for i in range(len(mutex_name)):
        n, seed = rand(seed)
        mutex_name[i] = mutex_name[n % len(mutex_name)]

    return mutex_name.decode()


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename|hash')
    sys.exit(0)

arg1 = sys.argv[1]

if os.path.isfile(arg1):

    # Get the file contents SHA-256 hash
    digest = get_file_sha256(arg1)

else:

    if len(arg1) != 64:
        print('Error: Invalid SHA-256 hash')
        sys.exit(1)
    digest = binascii.unhexlify(arg1)

# Make UUID string from digest
uuid = make_uuid_str(digest)
print('uuid:', uuid)

# Make mutex name from digest
mutex_name = make_mutex_name(digest)
print('mutex name:', mutex_name)
