#This file creates a PGP key pair using the gnupg library

import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

#created keys will be stored in this folder
#gpg = gnupg.GPG(gnupghome='/.gnupg')

gpg.encoding = 'utf-8'

#inputs to generate the keys
input_data = gpg.gen_key_input(
    name_email = 'yusuf',
    key_type="RSA",
    key_length=1024,
    passphrase='yusuf',
)

#generating the key pairs (public and private)
key = gpg.gen_key(input_data)

#catch case where key did not generate
if not key:
    print("Key generation failed.")
else:
    print("Key generation result:", key)

#export the public key
public_key = gpg.export_keys(key.fingerprint)

with open('yusuf_public_key.asc', 'w') as f:
    f.write(public_key)

#TODO: send this public key to Bob/ other clients