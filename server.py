import socket
import json
import os
import gnupg
import random

# Creating the socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "0.0.0.0"
port = 1200

# Binding to socket
serversocket.bind((host, port))


def load_data(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def save_data(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)


def accessDatabase(clientsocket, email):
    print("Database Accessed")


def register_user(username, public_key):
    filename = 'users.json'
    data = load_data(filename)
    if username not in data['users']:
        certificateUnprotected = username + "///" + public_key

        script_dir = os.path.dirname(os.path.abspath(__file__))
        gpg_home = os.path.join(script_dir, '.gnupg')
        gpg = gnupg.GPG(
            gnupghome=gpg_home, gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

        # with open(ptfile, 'rb') as f:
        #     #encrypting the file
        #     status = gpg.encrypt_file(f, recipients=['alice@example.com'],
        #                             output=ptfile + ".encrypted")
        # certificateProtected = gpg.encrypt(certificateUnprotected, recipients=[username], sign='CA@example.com', passphrase='passphrase')
        certificateProtected = gpg.sign(
            certificateUnprotected, passphrase='passphrase')
        print(username + "\n" + str(certificateProtected))

        data['users'][username] = {
            "public_key": public_key,
            "certificate": str(certificateProtected),
        }

        save_data(filename, data)
        return True
    print("This brudda is already here")
    return False  # User already exists


def login(clientsocket):
    print("LOGIN ATTEMPT")
    data = load_data('users.json')
    # emailRequest = "Enter Email: "
    # clientsocket.send(emailRequest.encode('utf-8'))
    emailResponse = clientsocket.recv(1024).decode().strip()
    while True:
        if emailResponse not in data['users']:
            if (emailResponse in ['q', 'Q']):
                clientsocket.send("Bye Bye".encode('utf-8'))
                clientsocket.close()
            else:
                retryEmail = "Username not found. Please try again or quit and register."
                clientsocket.send(retryEmail.encode('utf-8'))
                emailResponse = clientsocket.recv(1024).decode().strip()
        else:
            break
    clientsocket.send("checking identity...".encode('utf-8'))
    pubKey = data['users'][emailResponse]['public_key']

    script_dir = os.path.dirname(os.path.abspath(__file__))
    gpg_home = os.path.join(script_dir, '.gnupg')
    gpg = gnupg.GPG(gnupghome=gpg_home,
                    gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

    import_result = gpg.import_keys(pubKey)

    if not import_result.counts:
        raise ValueError("Public key import failed.")

    nonce = str(random.randint(1, 10000000000000000000000000))

    encrypted_nonce = gpg.encrypt(
        # nonce, import_result.fingerprints[0], always_trust=True)
        nonce, recipients=[emailResponse])

    if not encrypted_nonce.ok:
        raise ValueError("Encryption failed:", encrypted_nonce.status)
   # decrypted_nonce = gpg.decrypt(str(encrypted_nonce), passphrase="passphrase")
    clientsocket.send(str(encrypted_nonce).encode('utf-8'))
    encrypted_nonce_client = clientsocket.recv(1024).decode()
    decrypted_nonce_client = gpg.decrypt(encrypted_nonce_client, passphrase="passphrase")
    print(str(decrypted_nonce_client))
    if str(decrypted_nonce_client) == nonce:
        print("LOGIN SUCCESSFUL")
        #TODO: ASK USER IF THEY WANT TO SEND OR RECEIVE - CREATE FUNCTION TO MANAGE THIS
    else:
        print("FAILURE: NONCES DO NOT MATCH")
        clientsocket.close()


def signup(clientsocket):
    print("SIGN UP")
    email = clientsocket.recv(1024).decode().strip()
    filename = 'users.json'
    data = load_data(filename)
    if email in data['users']:
        clientsocket.send("True".encode('utf-8'))
        clientsocket.send(
            "You are already registered! Taking you back to the main menu...".encode('utf-8'))
        clientsocket.send(
            "Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('utf-8'))
        loginmanagement(clientsocket.recv(1024).decode(), clientsocket)
    else:
        clientsocket.send("False".encode('utf-8'))
        public_key = clientsocket.recv(1024).decode()
        register_user(email, public_key)


def loginmanagement(authmessage, clientsocket):
    while (authmessage not in ["LOGIN","SIGN UP","Q"]):
        clientsocket.send("UNKNOWN COMMAND. Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('UTF-8'))
        authmessage = clientsocket.recv(1024).decode()
    if authmessage == "LOGIN":
        login(clientsocket)  # go to login function
    elif authmessage == "SIGN UP":
        signup(clientsocket)  # go to sign in function
    elif authmessage == "Q":
        clientsocket.send("Bye Bye".encode('utf-8'))
        clientsocket.close()
    # else:
    #     clientsocket.send("ERROR: UNKOWN COMMAND. Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('utf-8'))
    #     loginmanagement(clientsocket.recv(1024).decode(), clientsocket)


# Main method to manage initial connection
def main():
    # Starting TCP listener
    serversocket.listen(3)

    while True:
        # Starting the connection
        clientsocket, address = serversocket.accept()

        print("received connection from " + str(address))

        # Message sent to client after successful connection
        message = 'Hello! Thank you for connecting to the server' + \
            "\r\nDo you want to [LOGIN] or [SIGN UP] or [Q]uit?"  # Login or Sign up
        clientsocket.send(message.encode('utf-8'))
        loginmanagement(clientsocket.recv(1024).decode(), clientsocket)



if __name__ == "__main__":
    main()
