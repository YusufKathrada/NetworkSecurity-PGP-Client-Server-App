import socket
import os
import gnupg

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome = gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

gpg.encoding = 'utf-8'

def generate_key_pair(email, passphrase):
    
    #inputs to generate the keys
    input_data = gpg.gen_key_input(
        name_email = email,
        key_type="RSA",
        key_length=1024,
        passphrase=passphrase,
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

    with open(email + '_public_key.asc', 'w') as f:
        f.write(public_key)
    
    return public_key

def userMenu(clientsocket):
    while True:
        message = clientsocket.recv(1024)
        print(message.decode('utf-8'))
        option = input()
        clientsocket.send(option.encode('utf-8'))

        if option == "SIGN UP":
            email = input("Please enter your email\n")
            clientsocket.send(email.encode('utf-8'))

            isRegistered = clientsocket.recv(1024).decode('utf-8')

            if isRegistered == "True":
                continue
            
            passphrase = input("Please enter a passphrase. You will need to save this for later!\n").strip()

            # generate key pair
            public_key = generate_key_pair(email, passphrase)
            clientsocket.send(public_key.encode('utf-8'))

            clientsocket.close()
            return
        
        elif option == "LOGIN":
            email = input("Please enter your email\n")
            clientsocket.send(email.encode('utf-8'))
            emailResponse = clientsocket.recv(1024).decode()
            while emailResponse != "checking identity...":
                email = input("This user does not exist, please resubmit a valid email:\n")
                clientsocket.send(email.encode('utf-8'))
                emailResponse = clientsocket.recv(1024).decode()
                #print(emailResponse)
            encryptedNonceToClient = clientsocket.recv(1024).decode()
            #print(str(encryptedNonceToClient))
            passphraseClient = input("Please enter your passphrase\n").strip()

            decryptedNonceClient = gpg.decrypt(encryptedNonceToClient, passphrase=passphraseClient)
            #print(str(decryptedNonceClient))
            
            key_data = open('CA_public_key.asc').read()
            import_result = gpg.import_keys(key_data)
            # print(str(import_result.fingerprints[0]))
            # encryptedNonceToServer = gpg.encrypt(str(decryptedNonceClient), import_result.fingerprints[0], always_trust=True)
            encryptedNonceToServer = gpg.encrypt(str(decryptedNonceClient), recipients=['CA@example.com'])

            clientsocket.send(str(encryptedNonceToServer).encode('utf-8'))

        elif option == "Q":
            clientsocket.close()
            return
        else:
            continue
        


def main():
    clientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    #host = "0.0.0.0"
    host = socket.gethostname()

    port = 1200

    clientsocket.connect((host, port)) #You can substitue the host with the server IP

    userMenu(clientsocket)

if __name__ == "__main__":
    main()
