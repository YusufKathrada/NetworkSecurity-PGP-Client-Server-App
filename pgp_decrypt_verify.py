# program that decrypts a file with Bob's private key 
# and verifies it with Alice's public key
import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

gpg.encoding = 'utf-8'

ptext = "plaintextAlice.txt.pgp"

stream = open(ptext, 'rb')
decrypted_data = gpg.decrypt_file(stream, passphrase='passphrase', output=ptext + ".verified")

print(decrypted_data.status)
print(decrypted_data.valid)
print(decrypted_data.trust_text)