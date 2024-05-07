# Use Alice's public key to encrypt a file 
# and returns the encrypted file ending with .encrypted

import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

#plain text file
#TODO: change this to accept user input
ptfile = "testFile.txt"

with open(ptfile, 'rb') as f:
    #encrypting the file
    status = gpg.encrypt_file(f, recipients=['alice@example.com'],
                              output=ptfile + ".encrypted")

print(status.ok)
# check for errors (eg. key not imported or not correct)
print(status.stderr)
                                             