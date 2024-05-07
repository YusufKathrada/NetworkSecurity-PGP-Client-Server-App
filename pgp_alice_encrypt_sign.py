# program that encrypts a file with Alice's private key 
# and signs it with Bob's public key
import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

gpg.encoding = 'utf-8'

ptext = "plaintextAlice.txt"

stream = open(ptext, 'rb')

# get the fingerprint of the key
fp = gpg.list_keys(True).fingerprints[0]

#TODO: change this to accept user input
# Should be bob instead of Alice here
# encrypt with bobs public key and sign with alices private key
# obviously, for now it shows alice encrypting with her own key
status = gpg.encrypt_file(stream, recipients=['alice@example.com'], sign=fp, passphrase='passphrase', output=ptext + ".pgp")
#TODO: Send this file to the other client
print(status.ok)
print(status.stderr)