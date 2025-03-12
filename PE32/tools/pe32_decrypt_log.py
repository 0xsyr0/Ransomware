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
import struct
import pe32_crypt


MIN_LOG_ENTRY_SIZE = 2 * 8 + pe32_crypt.AES_CTR_NONCE_SIZE


#
# Main
#
if len(sys.argv) != 2:
    print('Usage:', os.path.basename(sys.argv[0]), 'filename')
    sys.exit(0)

filename = sys.argv[1]

with io.open('./keydata.bin', 'rb') as f:
    keydata = f.read()

# Read encrypted log data
with io.open(filename, 'rb') as f:
    enc_log_data = f.read()

log_data = b''

msg_count = 0
pos = 0

while pos + MIN_LOG_ENTRY_SIZE <= len(enc_log_data):

    # Parse log entry
    key_index, msg_len = struct.unpack_from('>2Q', enc_log_data, pos)
    pos += 16
    nonce = enc_log_data[pos : pos + pe32_crypt.AES_CTR_NONCE_SIZE]
    pos += pe32_crypt.AES_CTR_NONCE_SIZE
    enc_msg = enc_log_data[pos : pos + msg_len]
    pos += msg_len

    print('log message %d: %d' % (msg_count, msg_len))

    keydata_entry = pe32_crypt.get_keydata_entry(keydata, key_index)
    if not keydata_entry:
        print('Error: Invalid key index in entry %d' % i)
        break

    # AES CTR decrypt data
    key = keydata_entry[:pe32_crypt.AES_KEY_SIZE]
    msg = pe32_crypt.aes_ctr_decrypt(enc_msg, key, nonce)

    log_data += msg
    msg_count += 1

print('log messages:', msg_count)

# Save log data
new_filename = filename + '.dec'
with io.open(new_filename, 'wb') as f:
    f.write(log_data)
