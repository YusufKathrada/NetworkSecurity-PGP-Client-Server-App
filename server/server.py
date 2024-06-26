import socket
import json
import os
import gnupg
import random
import threading
import datetime
import sys
from PIL import Image
import io
import base64
import hashlib

CApassphrase = "U0xNVEFBMDA3TVNMR1JFMDAxS1RIWVVTMDAx"

script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome=gpg_home,
                gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')


# client receive
RECEIVE_REQUEST = """RECEIVE
SENDER: {sender}
RECIPIENT: {recipient}
TIMESTAMP: {timestamp}
///SENDER_CERTIFICATE: {sender_certificate}
///CASIGNATURE: {CAsignature}/////
{message}"""

# Function that loads data from a JSON file
def load_data(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

# Function that saves data to a JSON file
def save_data(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

# Function that deletes received messages from the JSON file
def delete_received_messages(filename, data):
    with open(filename, 'w') as file:
        # Write the initial part of the JSON structure
        file.write('{"messages": \n')
        json.dump(data, file, indent=4)
        # Close the JSON object
        file.write('}')

# Function that creates the message digest of a message
def create_message_digest(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    digest = hashlib.sha256(message).hexdigest()
    return digest

# Function that prompts the user with the options to SEND, RECEIVE or QUIT
def accessMenu(serversocket, email):
    # Prompt the user with the menu options
    menuMessage = "Do you want to [SEND] or [RECEIVE] or [Q]uit?"
    serversocket.send(menuMessage.encode('utf-8'))
    menuOption = serversocket.recv(1024).decode().strip()

    # Validate the user's input
    while menuOption not in ["SEND", "RECEIVE", "Q"]:
        serversocket.send("UNKNOWN COMMAND. Do you want to [SEND] or [RECEIVE] or [Q]uit?".encode('UTF-8'))
        menuOption = serversocket.recv(1024).decode()

    # Handle the selected menu option
    if menuOption == "SEND":
        serversocket.send("SERVER IS READY TO RECEIVE".encode('utf-8'))
        serverReceive(serversocket, email)
        print("GOING BACK TO ACCESS MENU")
        accessMenu(serversocket, email)
    elif menuOption == "RECEIVE":
        serversocket.send("YOUR IMAGES ARE BEING DELIVERED...".encode('UTF-8'))
        serverSend(serversocket, email)
        accessMenu(serversocket, email)
    elif menuOption == "Q":
        serversocket.send("Bye Bye".encode('utf-8'))
        serversocket.close()

# Function that sends a message to the client
def send_message(s, header):
    s.send(header.encode('utf-8'))
    s.send(b'END')

# Function that receives a message from the client
def serverReceive(serversocket, email):
    print("CLIENT IS ATTEMPTING TO SEND")
    serversocket.send(
        "Please enter the email of the recipient:".encode('utf-8'))
    recipientEmail = serversocket.recv(1024).decode().strip()

    print("Recipient: " + recipientEmail)

    filename = 'users.json'
    data = load_data(filename)
    # if recipientEmail not found in users.json, prompt user to try again
    while recipientEmail not in data['users']:
        serversocket.send(
            "Recipient not found. Please try again.".encode('utf-8'))
        recipientEmail = serversocket.recv(1024).decode().strip()

        if recipientEmail == "Q":
            serversocket.close()
            return

    serversocket.send("Recipient found!".encode('utf-8'))
    serversocket.send(data['users'][recipientEmail]
                      ['public_key'].encode('utf-8'))
    all_data = ""
    # Receive the message data
    try:
        while True:
            data = serversocket.recv(1024).decode('utf-8')
            if not data:
                print("No more data received.")
                break
            all_data += data
            if all_data.endswith('END'):  # Check for the end signal
                all_data = all_data[:-3]  # Remove the end signal from the data
                print("End of data signal received.")
                break
    except Exception as e:
        print(f"Error receiving data: {e}")

    # split header and image data
    split_message = all_data.split("/////")
    header = split_message[0]
    header_arr = header.split("///")
    search_string = "SENDER_CERTIFICATE: "
    index = header_arr[1].find(search_string)
    sender_certificate = header_arr[1][(index + len(search_string)):]
    message_data = split_message[1]
    print(header_arr[0] + header_arr[1])

    # Save the message to the json file
    filename = 'messages.json'
    data = load_data(filename)

    data['messages'].append({
        "sender": email,
        "recipient": recipientEmail,
        "timestamp": datetime.datetime.now().isoformat(),
        "senderCertificate": (sender_certificate + "///" + header_arr[2]),
        "messageContent": message_data
    })

    save_data(filename, data)
    print("Message saved")
    serversocket.send("Message sent successfully!".encode('utf-8'))

# Function that initiates the sending of messages to the client
def serverSend(serversocket, email):
    print("RECEIVING")
    filename = 'messages.json'
    data = load_data(filename)
    waiting_messages = []
    sender_certificate_arr = []
    messages = []
    message_senders = []
    # append all messages for the recipient to waiting_messages
    for message in data['messages']:
        if (message['recipient'] == email):
            waiting_messages.append(message['messageContent'])
            sender_certificate_arr.append(message['senderCertificate'])
            message_senders.append(message['sender'])
        else:
            messages.append(message)
    data_to_save = {'messages': messages}
    # delete all messages for the recipient from the json file
    delete_received_messages(filename, messages)
    if (waiting_messages == []):
        response = "No messages currently stored for recipient " + email
        print(response)
        serversocket.send(response.encode('utf-8'))
    else:
        # Send all messages to the client
        for i in range(len(waiting_messages)):
            print("Sending message number " + str(i))
            serversocket.send(str(i).encode('utf-8'))
            print(serversocket.recv(1024).decode())
            serversocket.send("SEND ACK".encode('utf-8'))
            message = waiting_messages[i]
            encrypted_message_digest = create_message_digest(message)
            message_for_signing = datetime.datetime.now().isoformat() + "\n" + encrypted_message_digest
            ca_signed_message = gpg.sign(message_for_signing,
                              passphrase=CApassphrase, clearsign=True)
            message_length = len(message)
            # wait for an acknowledgement
            ack = serversocket.recv(1024).decode().strip()
            print("ACK: ", ack)
            if ack == 'ACK':
                # Send the message
                send_message(serversocket, RECEIVE_REQUEST.format(
                    sender=message_senders[i],
                    recipient=email,
                    timestamp=datetime.datetime.now().isoformat(),
                    sender_certificate=sender_certificate_arr[i],
                    CAsignature=ca_signed_message,
                    message=message
                ))

            print(serversocket.recv(1024).decode())
        complete_message = "All messages stored for the recipient have been sent"
        print(complete_message)
        serversocket.send(complete_message.encode('utf-8'))
        print(serversocket.recv(1024).decode())

# Function that registers a user
def register_user(username, public_key):
    # Load user data from JSON file
    filename = 'users.json'
    data = load_data(filename)

    # Check if user already exists
    if username not in data['users']:
        # Create the user's certificate
        certificateUnprotected = username + "///" + public_key
        certificateProtected = gpg.sign(
            certificateUnprotected, passphrase=CApassphrase)
        print(username + "\n" + str(certificateProtected))

        # Add user to the data dictionary
        data['users'][username] = {
            "public_key": public_key,
            "certificate": str(certificateProtected),
        }

        # Save the updated data to the JSON file
        save_data(filename, data)
        return True  # User successfully registered
    print("This brudda is already here")
    return False  # User already exists

# Function that logs a user in
def login(serversocket):
    print("LOGIN ATTEMPT")
    data = load_data('users.json')
    emailResponse = serversocket.recv(1024).decode().strip()
    while True:
        if emailResponse not in data['users']:
            if (emailResponse in ['q', 'Q']):
                serversocket.send("Bye Bye".encode('utf-8'))
                serversocket.close()
            else:
                retryEmail = "Username not found. Please try again or quit and register."
                serversocket.send(retryEmail.encode('utf-8'))
                emailResponse = serversocket.recv(1024).decode().strip()
        else:
            break
    serversocket.send("checking identity...".encode('utf-8'))
    pubKey = data['users'][emailResponse]['public_key']

    import_result = gpg.import_keys(pubKey)

    if not import_result.counts:
        raise ValueError("Public key import failed.")
    
    # Generate a random nonce
    nonce = str(random.randint(1, 10000000000000000000000000))
    # Encrypt the nonce with the user's public key
    encrypted_nonce = gpg.encrypt(
        nonce, recipients=[emailResponse], always_trust=True)
    # Check if the encryption was successful
    if not encrypted_nonce.ok:
        raise ValueError("Encryption failed:", encrypted_nonce.status)
    serversocket.send(str(encrypted_nonce).encode('utf-8'))

    # Receives "please send public key"
    serversocket.recv(1024).decode()

    # access CA public key.asc file and send to client
    with open('CA1_public_key.asc', 'r') as file:
        CApublickey = file.read()
        serversocket.send(CApublickey.encode('utf-8'))
    # receive encrypted nonce from client, encrypted with CA public key
    encrypted_nonce_client = serversocket.recv(1024).decode()
    # decrypt nonce from client with CA private key
    decrypted_nonce_client = gpg.decrypt(
        encrypted_nonce_client, passphrase=CApassphrase, always_trust=True)
    # check if decrypted nonce from client matches the orginal nonce
    if str(decrypted_nonce_client) == nonce:
        print("LOGIN SUCCESSFUL")
        loginSuccessMsg = "Login Success"
        serversocket.send(loginSuccessMsg.encode('utf-8'))
        # receive "please send certificate"
        serversocket.recv(1024).decode()
        client_certificate = data['users'][emailResponse]['certificate']
        # send certificate
        serversocket.send(client_certificate.encode('utf-8'))
        accessMenu(serversocket, emailResponse)
    else:
        print("FAILURE: NONCES DO NOT MATCH")
        loginFailMessage = "Login Failure"
        serversocket.send(loginFailMessage.encode('utf-8'))
        serversocket.close()

# Function that allows a user to sign up
def signup(serversocket):
    print("SIGN UP")
    email = serversocket.recv(1024).decode().strip()
    filename = 'users.json'
    data = load_data(filename)
    if email in data['users']:
        serversocket.send("True".encode('utf-8'))
        serversocket.send(
            "You are already registered! Taking you back to the main menu...".encode('utf-8'))
        serversocket.send(
            "Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('utf-8'))
        loginmanagement(serversocket.recv(1024).decode(), serversocket)
    else:
        serversocket.send("False".encode('utf-8'))
        public_key = serversocket.recv(1024).decode()
        register_user(email, public_key)

# Function that manages the login process
def loginmanagement(authmessage, serversocket):
    while (authmessage not in ["LOGIN", "SIGN UP", "Q"]):
        serversocket.send(
            "UNKNOWN COMMAND. Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('UTF-8'))
        authmessage = serversocket.recv(1024).decode()
    if authmessage == "LOGIN":
        login(serversocket)  # go to login function
    elif authmessage == "SIGN UP":
        signup(serversocket)  # go to sign in function

    elif authmessage == "Q":
        serversocket.send("Bye Bye".encode('utf-8'))
        serversocket.close()

# Function that handles the initial connection with the client
def clientHandler(serversocket, address):
    message = 'Hello! Thank you for connecting to the server' + \
        "\r\nDo you want to [LOGIN] or [SIGN UP] or [Q]uit?"  # Login or Sign up
    serversocket.send(message.encode('utf-8'))
    loginmanagement(serversocket.recv(1024).decode(), serversocket)


def main():
    # Creating the socket object
    initialsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "0.0.0.0"
    port = 1200

    # Binding to socket
    initialsocket.bind((host, port))
    # Starting TCP listener
    initialsocket.listen(3)

    while True:
        print("Server is listening for connections")
        # Starting the connection
        serversocket, address = initialsocket.accept()

        print("received connection from " + str(address))
        thread = threading.Thread(
            target=clientHandler, args=(serversocket, address))
        thread.start()


if __name__ == "__main__":
    main()
