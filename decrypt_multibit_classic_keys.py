#!/usr/bin/python

# decrypt_multibit_classic_keys.py - PrivKey extractor for Multibit Classic
# Copyright (C) 2017 HCP
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           1NyVDDmhZPcyKhyrkiUFZbqPPuiYxwTujb
#
#                      Thank You!

from __future__ import print_function

__version__ =  '0.4.0'

import hashlib, sys, os, getpass
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
import wallet_pb2

sha256 = hashlib.sha256
md5    = hashlib.md5


key_expander = aespython.key_expander.KeyExpander(256)

def wait_key():
    ''' Wait for a key press on the console and return it. '''
    result = None
    if os.name == 'nt':
        import msvcrt
        result = msvcrt.getch()
    else:
        import termios
        fd = sys.stdin.fileno()

        oldterm = termios.tcgetattr(fd)
        newattr = termios.tcgetattr(fd)
        newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, newattr)

        try:
            result = sys.stdin.read(1)
        except IOError:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)

    return result

def aes256_cbc_decrypt(ciphertext, key, iv):
    """decrypts the ciphertext using AES256 in CBC mode

    :param ciphertext: the encrypted ciphertext
    :type ciphertext: str
    :param key: the 256-bit key
    :type key: str
    :param iv: the 128-bit initialization vector
    :type iv: str
    :return: the decrypted ciphertext, or raises a ValueError if the key was wrong
    :rtype: str
    """
    block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    for i in xrange(0, len(ciphertext), 16):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )
    padding_len = plaintext[-1]
    # check for PKCS7 padding
    if not (1 <= padding_len <= 16 and plaintext.endswith(chr(padding_len) * padding_len)):
        raise ValueError('incorrect password')
    return str(plaintext[:-padding_len])


multibit_hd_password = None
def load_wallet(wallet_file, get_password_fn):
    """load and if necessary decrypt a bitcoinj wallet file

    :param wallet_file: an open bitcoinj wallet file
    :type wallet_file: file
    :param get_password_fn: a callback returning a password that's called iff one is required
    :type get_password_fn: function
    :return: the Wallet protobuf message or None if no password was entered when required
    :rtype: wallet_pb2.Wallet
    """

    # Check to see if this is an encrypted (OpenSSL style) wallet backup
    wallet_file.seek(0)
    magic_bytes = wallet_file.read(12)
    try:
        is_ossl_encrypted = magic_bytes.decode('base64').startswith(b'Salted__')
    except Exception:
        is_ossl_encrypted = False
    wallet_file.seek(0)

    if is_ossl_encrypted:
        ciphertext = wallet_file.read().decode('base64')
        assert len(ciphertext) % 16 == 0

        password = get_password_fn(False)  # False means the kdf below is fast
        if not password:
            return None

        # Derive the encryption key and IV
        salted_pw = password.encode('UTF-8') + ciphertext[8:16]
        key1 = md5(salted_pw).digest()
        key2 = md5(key1 + salted_pw).digest()
        iv   = md5(key2 + salted_pw).digest()

        # Decrypt the wallet
        plaintext = aes256_cbc_decrypt(ciphertext[16:], key1 + key2, iv)

        print(plaintext)
        
        return True
    
    else:
        print("Not a keyfile??")
        return False

if __name__ == '__main__':

    padding      = 6     # GUI widget padding
    progress_bar = None  # GUI progress bar

    # command-line specific code
    if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
        sys.exit('usage: descrypt_multibit_classic_keys.py multibit-classic-key-file')

    wallet_file = open(sys.argv[1], 'rb')

    def get_password_factory(prompt):
        def get_password(takes_long_arg_ignored):  # must return unicode
            encoding = sys.stdin.encoding or 'ASCII'
            if 'utf' not in encoding.lower():
                print('terminal does not support UTF; passwords with non-ASCII chars might not work', file=sys.stderr)
            password = getpass.getpass(prompt + ' ')
            if isinstance(password, str):
                password = password.decode(encoding)  # convert from terminal's encoding to unicode
            return password
        return get_password

    # These functions differ between command-line and GUI runs
    get_password  = get_password_factory('This wallet file is encrypted, please enter its password:')
    get_pin       = get_password_factory("This wallet's seed is encrypted with a PIN or password, please enter it:")
    display_error = lambda msg: print(msg, file=sys.stderr)

    # Load (and possibly decrypt) the wallet, retrying on bad passwords
    while True:
        try:
            wallet = load_wallet(wallet_file, get_password)
            if not wallet:  # if no password was entered
                sys.exit('cancelled')
            break
        except ValueError as e:
            display_error(str(e))
            if not e.args[0].startswith('incorrect password'):
                raise
    
    print("")
    print("Press any key to continue...")
    wait_key()
