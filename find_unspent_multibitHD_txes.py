#!/usr/bin/python

# find_unspent_multibitHD_txes.py
# Find unspent TXes within MultiBit HD wallets
# Copyright (C) 2017, HCP
# All rights reserved.
#
# Based on decrypt_bitcoinj_seed.pyw
# Copyright (C) 2014, 2016 Christopher Gurnee
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
import wallet_pb2, binascii, bitcoin

sha256 = hashlib.sha256
md5    = hashlib.md5


key_expander = aespython.key_expander.KeyExpander(256)

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

    wallet_file.seek(0)
    magic_bytes = wallet_file.read(12)
    
    wallet_file.seek(0, os.SEEK_END)
    wallet_size = wallet_file.tell()
    wallet_file.seek(0)

    if magic_bytes[2:6] != b"org." and wallet_size % 16 == 0:
        import pylibscrypt
        takes_long = not pylibscrypt._done  # if a binary library wasn't found, this'll take a while

        ciphertext = wallet_file.read()
        assert len(ciphertext) % 16 == 0

        password = get_password_fn(takes_long)
        if not password:
            return None

        # Derive the encryption key
        salt = '\x35\x51\x03\x80\x75\xa3\xb0\xc5'
        key  = pylibscrypt.scrypt(password.encode('utf_16_be'), salt, olen=32)

        # Decrypt the wallet ( v0.5.0+ )
        try:
            plaintext = aes256_cbc_decrypt(ciphertext[16:], key, ciphertext[:16])
            if plaintext[2:6] != b"org.":
                raise ValueError('incorrect password')
        except ValueError as e:
            if e.args[0] == 'incorrect password':

                # Decrypt the wallet ( < v0.5.0 )
                iv = '\xa3\x44\x39\x1f\x53\x83\x11\xb3\x29\x54\x86\x16\xc4\x89\x72\x3e'
                plaintext = aes256_cbc_decrypt(ciphertext, key, iv)

        global multibit_hd_password
        multibit_hd_password = password

    # Else it's not whole-file encrypted
    else:
        password  = None
        plaintext = wallet_file.read()

    # Parse the wallet protobuf
    pb_wallet = wallet_pb2.Wallet()
    try:
        pb_wallet.ParseFromString(plaintext)
    except Exception as e:
        msg = 'not a wallet file: ' + str(e)
        if password:
            msg = "incorrect password (or " + msg + ")"
        raise ValueError(msg)
    
    f = open('parsed_wallet.txt','w')
    f.write(pb_wallet.__str__())
    f.close()
    
    foundAddr = []
    
    for trans in pb_wallet.transaction:
      if trans.pool == 4:
        print("--------------------------------------------------------------------------------")
        print("TXID: " + binascii.hexlify(trans.hash))
        for out in trans.transaction_output:
          print("")
          faddr = bitcoin.bin_to_b58check(bitcoin.deserialize_script(out.script_bytes)[2])
          print("Addr: " + faddr)
          foundAddr.append(faddr)
          print("Amt: " + str(out.value * 0.00000001) + " BTC")
        print("")
        print("--------------------------------------------------------------------------------")
    
    seed = None
    
    sys.stdout.write('Finding Seed....')
    
    salt = pb_wallet.encryption_parameters.salt
    dkey = pylibscrypt.scrypt(password.encode('utf_16_be'), salt, olen=32)
    
    for wkey in pb_wallet.key:
      if wkey.type == 3:
        seed = aes256_cbc_decrypt(wkey.encrypted_deterministic_seed.encrypted_private_key, dkey, wkey.encrypted_deterministic_seed.initialisation_vector)
        break
        
    if not seed:
      print("No DETERMINISTIC_MNEMONIC seed found!")
      return None
    else:
      print("Done!")
    xprv = bitcoin.bip32_master_key(seed)
    
    xprvReceive = bitcoin.bip32_ckd(bitcoin.bip32_ckd(xprv, 2**31),0) #m/0'/0
    xprvChange = bitcoin.bip32_ckd(bitcoin.bip32_ckd(xprv, 2**31),1) #m/0'/1
    
    rcvAddr = []
    chgAddr = []
    rcvPrivKey = []
    chgPrivKey = []
    
    sys.stdout.write("Generating Addresses/Keys.")
    for x in range(0,1000):
      if x % 10 == 0:
        sys.stdout.write(".")
      childprivReceive = bitcoin.bip32_ckd(xprvReceive, x)
      childprivChange = bitcoin.bip32_ckd(xprvChange, x)
      
      pkeyReceive = bitcoin.bip32_extract_key(childprivReceive)
      pkeyChange = bitcoin.bip32_extract_key(childprivChange)
      
      #addressReceive = privtoaddr(pkeyReceive)
      #addressChange = privtoaddr(pkeyChange)
      rcvAddr.append(bitcoin.privtoaddr(pkeyReceive))
      chgAddr.append(bitcoin.privtoaddr(pkeyChange))
      
      rcvPrivKey.append(bitcoin.encode_privkey(pkeyReceive, 'wif_compressed'))
      chgPrivKey.append(bitcoin.encode_privkey(pkeyChange, 'wif_compressed'))
    print("Done!")  
    
    print("--------------------------------------------------------------------------------")
    
    for addy in foundAddr:
      if addy in rcvAddr:
        print("")
        print("Found Address: " + addy)
        print("PrivateKey: " + rcvPrivKey[rcvAddr.index(addy)])
      elif addy in chgAddr:
        print("")
        print("Found Change Address: " + addy)
        print("PrivateKey: " + chgPrivKey[chgAddr.index(addy)])
      else:
        print("")
        print("Address not found: " + addy)
    
    print("")
    print("--------------------------------------------------------------------------------")
      
    return pb_wallet


if __name__ == '__main__':

    if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
        sys.exit('usage: find_unspent_multibitHD_txes.py multibitHD-wallet-file')

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
                sys.exit('canceled')
            break
        except ValueError as e:
            display_error(str(e))
            if not e.args[0].startswith('incorrect password'):
                raise
