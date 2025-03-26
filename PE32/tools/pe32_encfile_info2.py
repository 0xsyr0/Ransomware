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
import pe32_crypt


# Round data
NUM_ROUNDS = 3
ROUNDDATA_ENTRY_SIZE = 89
ROUNDDATA_SIZE = NUM_ROUNDS * ROUNDDATA_ENTRY_SIZE
ENC_ROUNDDATA_SIZE = ROUNDDATA_SIZE + pe32_crypt.AES_GCM_MAC_TAG_SIZE

# Footer
NUM_ROUNDDATA = 2
FOOTER_SIZE = (pe32_crypt.NONCE2_DATA_SIZE +
               NUM_ROUNDDATA * ENC_ROUNDDATA_SIZE)


def get_encfile_info(filename: str,
                     footer_key: bytes, footer_nonce: bytes) -> bool:
    """Get encrypted file info"""

    with io.open(filename, 'rb') as f:

        file_stat = os.fstat(f.fileno())
        file_size = file_stat.st_size

        if file_size < FOOTER_SIZE:
            return False

        # Read footer
        f.seek(-FOOTER_SIZE, 2)
        footer = f.read(FOOTER_SIZE)

        # Nonce 2 data
        nonce2_data = footer[:pe32_crypt.NONCE2_DATA_SIZE]

        # Round data
        enc_round_data = footer[pe32_crypt.NONCE2_DATA_SIZE:]
        enc_round_data1 = enc_round_data[:ENC_ROUNDDATA_SIZE]
        enc_round_data2 = enc_round_data[ENC_ROUNDDATA_SIZE:]

        # Decrypt round data 1
        round_data1 = pe32_crypt.aes_gcm_decrypt(enc_round_data1,
                                                 footer_key, footer_nonce)
        if not round_data1:
            return False

        # Decrypt round data 2
        round_data2 = pe32_crypt.aes_gcm_decrypt(enc_round_data2,
                                                 footer_key, footer_nonce)
        if not round_data2:
            return False

        orig_file_size = file_size - FOOTER_SIZE
        print('original file size:', orig_file_size)

    # Save metadata
    with io.open(filename + '.metadata', 'wb') as f:
        f.write(nonce2_data + round_data1 + round_data2)

    return True


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Read footer key
with io.open('./footer_key.bin', 'rb') as f:
    footer_key = f.read(pe32_crypt.AES_KEY_SIZE)

# Read footer nonce
with io.open('./footer_nonce.bin', 'rb') as f:
    footer_nonce = f.read(pe32_crypt.AES_GCM_NONCE_SIZE)

# Get encrypted file info
if not get_encfile_info(filename, footer_key, footer_nonce):
    print('Error: file not encrypted or damaged')
    sys.exit(1)
