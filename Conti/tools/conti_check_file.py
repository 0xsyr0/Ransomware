# MIT License
#
# Copyright (c) 2024-2025 Andrey Zhdanov (rivitna)
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
import struct


# RSA
MAX_RSA_KEY_SIZE = 512

# Metadata
METADATA_SIZE = MAX_RSA_KEY_SIZE + 12 + 10


def check_encfile(filename: str) -> None:
    """Check encrypted file"""

    with io.open(filename, 'rb') as f:

        # Read metadata
        try:
            f.seek(-METADATA_SIZE, 2)
        except OSError:
            print('Error: The file is damaged or not encrypted')
            return

        metadata = f.read(METADATA_SIZE)

    orig_file_size, = struct.unpack_from('<Q', metadata,
                                         MAX_RSA_KEY_SIZE + 14)
    print('original file size:', orig_file_size)

    enc_mode = metadata[MAX_RSA_KEY_SIZE + 12]

    if enc_mode == 0x24:

        # full
        print('mode: full')

        num_chunks = 1
        chunk_space = 0
        chunk_size = orig_file_size

    elif enc_mode == 0x26:

        # header
        print('mode: header')

        num_chunks = 1
        chunk_space = 0
        chunk_size = min(HEADER_ENC_SIZE, orig_file_size)

    elif enc_mode == 0x25:

        # partly
        print('mode: partly')

        enc_percent = metadata[MAX_RSA_KEY_SIZE + 13]
        if enc_percent == 10:
            chunk_size = (orig_file_size // 100) * 4
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 15:
            chunk_size = (orig_file_size // 100) * 5
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 20:
            chunk_size = (orig_file_size // 100) * 7
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 25:
            chunk_size = (orig_file_size // 100) * 9
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 30:
            chunk_size = (orig_file_size // 100) * 10
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 35:
            chunk_size = (orig_file_size // 100) * 12
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 40:
            chunk_size = (orig_file_size // 100) * 14
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 50:
            chunk_size = (orig_file_size // 100) * 10
            num_chunks = 5
            chunk_space = chunk_size
        elif enc_percent == 60:
            chunk_size = (orig_file_size // 100) * 20
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 70:
            chunk_size = (orig_file_size // 100) * 23
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        elif enc_percent == 80:
            chunk_size = (orig_file_size // 100) * 27
            num_chunks = 3
            chunk_space = (orig_file_size - (chunk_size * 3)) // 2;
        else:
            print('encryption percent: unsupported')
            return

        print('encryption percent:', enc_percent)

    else:
        print('mode: unknown')
        return

    print('chunks:', num_chunks)
    print('chunk size: %08X' % chunk_size)
    print('chunk space: %08X' % chunk_space)


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

# Check encrypted file
check_encfile(filename)
