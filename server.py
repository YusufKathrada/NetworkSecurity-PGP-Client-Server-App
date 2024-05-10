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




script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
gpg = gnupg.GPG(gnupghome=gpg_home,
                gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')


def load_data(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data


def save_data(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)


def accessMenu(serversocket, email):
    menuMessage = "Do you want to [SEND] or [RECEIVE] or [Q]uit?"
    serversocket.send(menuMessage.encode('utf-8'))
    menuOption = serversocket.recv(1024).decode().strip()
    while menuOption not in ["SEND", "RECEIVE", "Q"]:
        serversocket.send(
            "UNKNOWN COMMAND. Do you want to [SEND] or [RECEIVE] or [Q]uit?".encode('UTF-8'))
        menuOption = serversocket.recv(1024).decode()
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

def serverReceive(serversocket, email):
    print("CLIENT IS ATTEMPTING TO SEND")
    serversocket.send("Please enter the email of the recipient:".encode('utf-8'))
    recipientEmail = serversocket.recv(1024).decode().strip()

    print("Recipient: " + recipientEmail)

    filename = 'users.json'
    data = load_data(filename)
    
    while recipientEmail not in data['users']:
        serversocket.send("Recipient not found. Please try again.".encode('utf-8'))
        recipientEmail = serversocket.recv(1024).decode().strip()
        
        if recipientEmail == "Q":
            serversocket.close()
            return

    serversocket.send("Recipient found!".encode('utf-8'))

    serversocket.send(data['users'][recipientEmail]['public_key'].encode('utf-8'))
    
    #TODO: Receive full image from client
    all_data = ""
    try:
        while True:
            print("Waiting for data...")
            data = serversocket.recv(1024).decode('utf-8')
            # print(str(data))
            if not data:
                print("No more data received.")
                break
            print(f"Received {len(data)} bytes of data.")
            all_data += data
            if all_data.endswith('END'):  # Check for the end signal
                all_data = all_data[:-3]  # Remove the end signal from the data
                print(all_data)
                print("End of data signal received.")
                break
    except Exception as e:
        print(f"Error receiving data: {e}")
    # encodedImage = serversocket.recv(1024).decode().strip()
    #print("Encrypted Message: " + encodedImage)

    filename = 'messages.json'
    data = load_data(filename)

    data['messages'].append({
        "sender": email,
        "recipient": recipientEmail,
        "timestamp": datetime.datetime.now().isoformat(),
        "messageContent": all_data
    })

    save_data(filename, data)
    print("Message saved")
    serversocket.send("Message sent successfully!".encode('utf-8'))



def serverSend(serversocket, email):
    #TODO: Delete message in json after sent
    print("RECEIVING")
    filename = 'messages.json'
    data = load_data(filename)
    waiting_messages = []
    message_senders = []
    for message in data['messages']:
        if(message['recipient'] == email):
            waiting_messages.append(message['messageContent'])
            message_senders.append(message['sender'])
    if(waiting_messages == []):
        response = "No messages currently stored for recipient " + email
        print(response)
        serversocket.send(response.encode('utf-8'))
    else:
        # for i in range(len(waiting_messages)):
        #     #TODO: Determine whether to send in segments according to stored array per message
        #     serversocket.send(message_senders[i].encode('utf-8'))
        #     print(serversocket.recv(1024).decode())
        #     serversocket.send(waiting_messages[i].encode('utf-8'))
        #     print(serversocket.recv(1024).decode())
        # complete_message = "All messages stored for the recipient have been sent"
        # print(complete_message)
        # serversocket.send(complete_message.encode('utf-8'))
        for i in range(len(waiting_messages)):
            print("Sending message number " + str(i))
            serversocket.send(message_senders[i].encode('utf-8'))
            #print(serversocket.recv(1024).decode(), "FLAG 1")
            print(serversocket.recv(1024).decode(), "FLAG 2")
            message = waiting_messages[i]
            message_length = len(message)

            ack = serversocket.recv(1024).decode().strip()  # wait for an acknowledgement
            print("ACK: ",ack)
            if ack == 'ACK':
                for j in range(0, message_length, 1024):
                    serversocket.send(message[j:j+1024].encode('utf-8'))
                serversocket.send("END".encode('utf-8'))
            print(serversocket.recv(1024).decode())
        complete_message = "All messages stored for the recipient have been sent"
        print(complete_message)
        serversocket.send(complete_message.encode('utf-8'))
        print(serversocket.recv(1024).decode())
        

            
    #encrypted_message = serversocket.recv(1024).decode()
    #decrypted_message = gpg.decrypt(encrypted_message, passphrase="passphrase")
    #print("Decrypted message: " + str(decrypted_message))
    #serversocket.send("Message received!".encode('utf-8'))
    #accessMenu(serversocket, email)


def register_user(username, public_key):
    filename = 'users.json'
    data = load_data(filename)
    if username not in data['users']:
        certificateUnprotected = username + "///" + public_key
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


def login(serversocket):
    print("LOGIN ATTEMPT")
    data = load_data('users.json')
    # emailRequest = "Enter Email: "
    # serversocket.send(emailRequest.encode('utf-8'))
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

    nonce = str(random.randint(1, 10000000000000000000000000))

    encrypted_nonce = gpg.encrypt(
        # nonce, import_result.fingerprints[0], always_trust=True)
        nonce, recipients=[emailResponse])

    if not encrypted_nonce.ok:
        raise ValueError("Encryption failed:", encrypted_nonce.status)
   # decrypted_nonce = gpg.decrypt(str(encrypted_nonce), passphrase="passphrase")
    serversocket.send(str(encrypted_nonce).encode('utf-8'))
    encrypted_nonce_client = serversocket.recv(1024).decode()
    decrypted_nonce_client = gpg.decrypt(
        encrypted_nonce_client, passphrase="passphrase")
    print(str(decrypted_nonce_client))
    if str(decrypted_nonce_client) == nonce:
        print("LOGIN SUCCESSFUL")
        loginSuccessMsg = "Login Success"
        serversocket.send(loginSuccessMsg.encode('utf-8'))
        accessMenu(serversocket, emailResponse)
    else:
        print("FAILURE: NONCES DO NOT MATCH")
        loginFailMessage = "Login Failure"
        serversocket.send(loginFailMessage.encode('utf-8'))
        serversocket.close()


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
    # else:
    #     serversocket.send("ERROR: UNKOWN COMMAND. Do you want to [LOGIN] or [SIGN UP] or [Q]uit?".encode('utf-8'))
    #     loginmanagement(serversocket.recv(1024).decode(), serversocket)


# Main method to manage initial connection
def clientHandler(serversocket,address):
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
        # Starting the connection
        serversocket, address = initialsocket.accept()

        print("received connection from " + str(address))
        thread = threading.Thread(target=clientHandler, args=(serversocket, address))
        thread.start()
        # Message sent to client after successful connection
        #######
        # message = 'Hello! Thank you for connecting to the server' + \
        #     "\r\nDo you want to [LOGIN] or [SIGN UP] or [Q]uit?"  # Login or Sign up
        # serversocket.send(message.encode('utf-8'))
        # loginmanagement(serversocket.recv(1024).decode(), serversocket)



if __name__ == "__main__":
    main()
