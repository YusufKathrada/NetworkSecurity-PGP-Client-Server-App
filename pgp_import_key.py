# imports a public key into the keyring 
# and sets the trust level to ultimate.
import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

#TODO: change this to accept user input
key_data = open('alice_public_key.asc').read()
import_result = gpg.import_keys(key_data)

gpg.trust_keys(import_result.fingerprints, 'TRUST_ULTIMATE')

mykeys = gpg.list_keys()

print(mykeys)