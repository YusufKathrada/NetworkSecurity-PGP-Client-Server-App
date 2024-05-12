import socket
import os
import gnupg
from PIL import Image
import base64
import io
import hashlib
import datetime
import zlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from os import urandom


# Get the directory of the script
script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
# Create a GPG object
gpg = gnupg.GPG(gnupghome=gpg_home,
                gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')

gpg.encoding = 'utf-8'

# Header Structure:

# client send
SEND_REQUEST = """SEND
SENDER: {sender}
RECIPIENT: {recipient}
TIMESTAMP: {timestamp}/////
{message}"""

SIGNATURE_AND_MESSAGE = """
SIGNATURE:
{timestamp}
{sender_email}
{message_digest}

MESSAGE: 
{filename}
{timestamp}
{caption}
{image_data}"""


# PGP MESSAGE Structure:
PGP_MESSAGE = """MESSAGE
SESSION_KEY_COMPONENT:
{recipient_email}
{session_key}

SIGNATURE_AND_MESSAGE:
{signature_and_message}"""




def session_decrypt(encrypted_image):
    key = b'abcdefghijklmnop'
    nonce = encrypted_image[encrypted_image.index(b"/////")+5:encrypted_image.index(b"//////")]
    key = encrypted_image[encrypted_image.index(b"//////")+6:]
    print("NONCE: ",nonce)    
    e_image_data = encrypted_image[:encrypted_image.index(b"/////")]
    decrypt_cipher = AES.new(key, AES.MODE_CTR,nonce=nonce)
    decrypted_image_b64 = decrypt_cipher.decrypt(e_image_data)    
    return decrypted_image_b64

def generate_session_key(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    cipher_text = cipher.encrypt(data)
    nonce = cipher.nonce
    decrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    #plain_text = decrypt_cipher.decrypt(cipher_text)
    print("NONCE NONCE: ",str(nonce))
    payload = base64.b64encode(cipher_text)
    #payload = base64.b64encode(cipher_text) + b"/////" + base64.b64encode(nonce)
    return (payload, nonce, key)


# Function that sends header messages
def send_message(s, header):
    s.send(header.encode('utf-8'))
    s.send(b'END')

def generate_key_pair(email, passphrase):
    # inputs to generate the keys
    input_data = gpg.gen_key_input(
        name_email=email,
        key_type="RSA",
        key_length=1024,
        passphrase=passphrase,
    )
    # generating the key pairs (public and private)
    key = gpg.gen_key(input_data)
    # catch case where key did not generate
    if not key:
        print("Key generation failed.")
    else:
        print("Key generation result:", key)

    # export the public key
    public_key = gpg.export_keys(key.fingerprint)
    with open(email + '_public_key.asc', 'w') as f:
        f.write(public_key)
    return public_key


def create_message_digest(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')

    digest = hashlib.sha256(message).hexdigest()
    return digest

def compress(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    # compress the message into zip form using zlib library
    compressed_message = zlib.compress(message) 
    return compressed_message

def decompress(compressed_message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    # decompress the message from zip form using zlib library
    decompressed_message = zlib.decompress(message)
    return decompressed_message
    

def encode_image(image_path, output_format='JPEG'):
    # Load the image
    img = Image.open(image_path)

    # Convert and compress the image
    img_buffer = io.BytesIO()
    img.save(img_buffer, format=output_format, optimize=True)

    # Base64 encode
    encoded_string = base64.b64encode(img_buffer.getvalue())
    return encoded_string


def fix_padding(data):
    # Check if the length of the data is divisible by 4
    # If not, add the necessary padding
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return data

def process_message_for_sending(recipient_email, image_path, sender_email, caption, passphrase):
    timestamp = datetime.datetime.now().isoformat()
    message_digest = create_message_digest(encode_image(image_path))
    filename = image_path
    image_data = encode_image(image_path).decode()
    # sign message digest with sender's private key
    encrypted_message_digest = gpg.sign(message_digest, passphrase=passphrase, keyid=sender_email)
    signature_and_message = SIGNATURE_AND_MESSAGE.format(
        # Signature
        timestamp=timestamp,
        sender_email=sender_email,
        message_digest=encrypted_message_digest,

        # Message
        filename=filename,
        caption=caption,
        image_data=image_data
        )
    compressed_signature_and_message = compress(signature_and_message)
    # encrypt with session key
    payload, nonce, key = generate_session_key(compressed_signature_and_message)
    #ENCRYPT KEY & NONCE WITH PUBLIC KEY
    nonce_and_key = f"{nonce}\n\n{key}"
    encrypted_nonce_and_key = gpg.encrypt(nonce_and_key, recipients=[recipient_email])
    encrypted_comp_signature_and_message = payload
    return PGP_MESSAGE.format(
        # Session key component
        recipient_email=recipient_email,
        session_key=str(encrypted_nonce_and_key),

        signature_and_message= encrypted_comp_signature_and_message
    )




def receive_message(clientsocket):
    # Receive data
    all_data = b""
    count = 0
    try:
        while True:
            # print("Waiting for data...")
            data = b"" + clientsocket.recv(1024)
            if count == 0:
                # print(data)
                count += 1
            if not data:
                print("No more data received.")
                break
            # print(f"Received {len(data)} bytes of data.")
            all_data += data
            if all_data.endswith(b'END'):  # Check for the end signal
                all_data = all_data[:-3]  # Remove the end signal from the data
                # print(all_data)
                print("End of data signal received.")
                break
    except Exception as e:
        print(f"Error receiving data: {e}")
    
    # decoded_data = all_data.decode('utf-8')
    # image_data_encrypted = base64.b64decode(decoded_data)
    # image_data_decrypted = session_decrypt(image_data_encrypted)
    # image_data = base64.b64decode(image_data_decrypted)

    #TODO: Split the header and the message data
    split_message = all_data.decode('utf-8').split("/////")
    header = split_message[0]
    message_data = split_message[1]
    image_data = process_message(message_data)
    process_image(image_data)
    return header
    
def process_message(d):
    session_key_start = d.index("SESSION_KEY_COMPONENT")
    session_key_end = d.index("\n\nSIGNATURE_AND_MESSAGE")
    session_key_component = d[session_key_start:session_key_end]
    # consists of recip email and session key
    session_key_component = session_key_component.split('\n')
    

    signature_and_message_start = d.index("SIGNATURE_AND_MESSAGE")+24
    signature_and_message_component = d[signature_and_message_start:]

    #decrypt the session key


def process_image(d):
    # Decode and save image
    try:
        print("Decoding image data...")
        data = d
        padded_data = fix_padding(data)
        encoded_again = padded_data.encode('utf-8')
        image_data = base64.b64decode(encoded_again)
        # print(image_data)
    except Exception as e:
        print(f"Failed to decode image data: {e}")
        return

    try:
        print("Saving image...")
        image = Image.open(io.BytesIO(image_data))
        # print(str(image))
        filename = input("Enter the name you wish to save the image as: \n")
        # TODO: if filename already exists ask user if they want to overwrite existing image.
        image.save(b"./received_images/" + filename.encode('utf-8') +
                   ".jpeg".encode('utf-8'), format='JPEG')
        print("Image saved successfully.")
    except Exception as e:
        print(f"Failed to save image: {e}")
    
#     #? WHEN TO USE THIS?
#     recipientPublicKey = clientsocket.recv(1024).decode()   
#     #TODO: ENCRYPT ENCRYPT
#     image_path = 'images\image3.jpg'
#     send_image_data(clientsocket, image_path)
#     print(clientsocket.recv(1024).decode())

def clientSend(clientsocket, email, passphrase):
    print(clientsocket.recv(1024).decode())
    recipient = input()
    clientsocket.send(recipient.encode('utf-8'))
    recipientValidityResponse = clientsocket.recv(1024).decode()

    while recipientValidityResponse == "Recipient not found. Please try again.":
        print(recipientValidityResponse)
        recipient = input()
        if recipient == "Q":
            clientsocket.send(recipient.encode('utf-8'))
            exit()
        else:
            clientsocket.send(recipient.encode('utf-8'))
            recipientValidityResponse = clientsocket.recv(1024).decode()
    
    
    recipientPublicKey = clientsocket.recv(1024).decode()   #? <-----  WHEN WE GONNA USE THIS?
    #TODO: Change to accept user input
    image_path = 'images\image3.jpg'


    caption = input("Enter a caption for the image: \n")
    

    send_request = SEND_REQUEST.format(
    sender=email,
    recipient=recipient,
    timestamp=datetime.datetime.now().isoformat(),
    message= process_message_for_sending(recipient, image_path, email, caption, passphrase))

    send_message(clientsocket, send_request)

    print(clientsocket.recv(1024).decode())


def clientReceive(clientsocket, email, passphrase):
    response = clientsocket.recv(1024).decode()
    #count = 1
    if (response.startswith("No")):
        print(response)
        accessManagement(clientsocket, email, passphrase)
    else:
        while (not (response.strip().startswith("All messages stored"))):
            clientsocket.send(
                "Please send any messages stored".encode('utf-8'))
            print("Message " + response + ": \n---------------------------- ")

            
            clientsocket.send('ACK'.encode('utf-8'))  # send acknowledgement

            header = receive_message(clientsocket)
            print(header)
            header_split = (header.split('\n')) #splice from space
            print("Sender is: " + (header_split[1])[8:]) #change response to be sender retrieved from message header


            
            print("Image has been received.")
            clientsocket.send("Are there any other messages?".encode('utf-8'))
            response = clientsocket.recv(1024).decode()
            #count += 1
        print(response)
        #TODO: More formal header possibly
        clientsocket.send("All messages received".encode('utf-8'))


def accessManagement(clientsocket, email, passphrase):
    print(clientsocket.recv(1024).decode())
    menuOption = input()
    clientsocket.send(menuOption.encode('utf-8'))
    modeResponse = clientsocket.recv(1024).decode()
    print(modeResponse)
    while modeResponse == "UNKNOWN COMMAND. Do you want to [SEND] or [RECEIVE] or [Q]uit?":
        menuOption = input()
        clientsocket.send(menuOption.encode('utf-8'))
        modeResponse = clientsocket.recv(1024).decode()
        print(modeResponse)
    if menuOption == "Q":
        print("Quitting")
        exit()
    elif menuOption == "SEND":
        clientSend(clientsocket, email, passphrase)
        accessManagement(clientsocket, email, passphrase)
    elif menuOption == "RECEIVE":
        clientReceive(clientsocket, email, passphrase)
        accessManagement(clientsocket, email, passphrase)


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
            passphrase = input(
                "Please enter a passphrase. You will need to save this for later!\n").strip()
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
                email = input(
                    "This user does not exist, please resubmit a valid email:\n")
                clientsocket.send(email.encode('utf-8'))
                emailResponse = clientsocket.recv(1024).decode()
            encryptedNonceToClient = clientsocket.recv(1024).decode()
            passphraseClient = input("Please enter your passphrase\n").strip()

            decryptedNonceClient = gpg.decrypt(
                encryptedNonceToClient, passphrase=passphraseClient)
            print(str(decryptedNonceClient))
            encryptedNonceToServer = gpg.encrypt(
                str(decryptedNonceClient), recipients=['CA@example.com'])

            clientsocket.send(str(encryptedNonceToServer).encode('utf-8'))
            attemptResponse = clientsocket.recv(1024).decode()
            if attemptResponse == "Login Failure":
                print("Incorrect Passphrase or Public Key. Disconnecting.")
                exit()
            else:
                accessManagement(clientsocket, email, passphraseClient)

        elif option == "Q":
            clientsocket.close()
            return
        else:
            continue


def main():
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = socket.gethostname()
    port = 1200

    clientsocket.connect((host, port))
    userMenu(clientsocket)


if __name__ == "__main__":
    main()
