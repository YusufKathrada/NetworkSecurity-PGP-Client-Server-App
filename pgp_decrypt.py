# Use Alice's private key to decrypt the file 
# and return the decrypted file ending with .decrypted

import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

#plain text file
ptfile = "testFile.txt.encrypted"

with open(ptfile, 'rb') as f:
    #decrypting the file, must include correct passphrase from pgp_genkey.py
    status = gpg.decrypt_file(f, passphrase= 'passphrase', output=ptfile + ".decrypted")

print(status.ok)
# check for errors (eg. key not imported or not correct)
print(status.stderr)