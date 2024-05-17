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

client_certificate = ""

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
TIMESTAMP: {timestamp}
///SENDER_CERTIFICATE: {sender_certificate}/////
{message}"""

SIGNATURE_AND_MESSAGE = """
SIGNATURE:
{timestamp}
{sender_email}
///{message_digest}

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

# Function that decrypts the session key
def session_decrypt(payload, nonce, key):
    # Convert the key and nonce to bytes
    bytekey = key.encode('latin1').decode('unicode_escape').encode('latin1')
    bytenonce = nonce.encode('latin1').decode('unicode_escape').encode('latin1')
    # Create a decrypt cipher using AES in CTR mode
    decrypt_cipher = AES.new(bytekey, AES.MODE_CTR, nonce=bytenonce)
    # Decrypt the payload
    decrypted_payload_b64 = decrypt_cipher.decrypt(payload)
    return decrypted_payload_b64

# Function that generates the session key and nonce
def generate_session_key(data):
    # Generate a random session key
    key = get_random_bytes(16)
    # Create a cipher object using AES in CTR mode
    cipher = AES.new(key, AES.MODE_CTR)
    # Encrypt the data using the session key
    cipher_text = cipher.encrypt(data)
    # Get the nonce value from the cipher object
    nonce = cipher.nonce
    # Encode the cipher text in base64
    payload = base64.b64encode(cipher_text)
    return payload, nonce, key


# Function that sends header messages
def send_message(s, header):
    s.send(header.encode('utf-8'))
    s.send(b'END')

# Function that generates the initial private and public key pair for a new user on sign
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
    with open("public_keys/" + email + '_public_key.asc', 'w') as f:
        f.write(public_key)
    return public_key


# Function that creates the message digest
def create_message_digest(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    digest = hashlib.sha256(message).hexdigest()
    return digest


# Function that compresses the message
def compress(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    # compress the message into zip form using zlib library
    compressed_message = zlib.compress(message)
    return compressed_message


# Function that decompresses the message
def decompress(message):
    if isinstance(message, str):
        # Check if the message is in byte form - if not, encode it
        message = message.encode('utf-8')
    # decompress the message from zip form using zlib library
    decompressed_message = zlib.decompress(message)
    return decompressed_message


# Function that encodes the image in base 64
def encode_image(image_path, output_format='JPEG'):
    try:
        # Load the image
        img = Image.open(image_path)
        img_buffer = io.BytesIO()
        img.save(img_buffer, format=output_format, optimize=True)
        # Base64 encode
        encoded_string = base64.b64encode(img_buffer.getvalue())
        return encoded_string

    except Exception as e:
        print(f"Failed to load image: {e}")
        exit()


# Function that fixes padding of encoded data
def fix_padding(data):
    # Check if the length of the data is divisible by 4, if not, add the necessary padding
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return data


# Function that processes the message for sending
def process_message_for_sending(recipient_email, image_path, sender_email, caption, passphrase, image_name):
    timestamp = datetime.datetime.now().isoformat()
    # encode image in base64
    image_data = encode_image(image_path)
    # create message digest
    message_digest = create_message_digest(image_data)
    filename = image_name
    image_data = image_data.decode()
    # sign message digest with sender's private key
    private_keys = gpg.list_keys(secret=True)
    key_id = None
    # find the key id for the sender's email
    for key in private_keys:
        if sender_email in key['uids'][0]:
            key_id = key['keyid']
            break
    if not key_id:
        print("NO KEY FOUND FOR PROVIDED IDENTIFIER")
    # sign the message digest with the sender's private key
    encrypted_message_digest = gpg.sign(
        message_digest, passphrase=passphrase, keyid=key_id, clearsign=True)
    # create the signature and message
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
    # compress the signature and message
    compressed_signature_and_message = compress(signature_and_message)
    # encrypt with session key
    payload, nonce, key = generate_session_key(
        compressed_signature_and_message)
    # encrypt the session key and nonce with the recipient's public key
    nonce_and_key = f"{nonce}\n\n{key}"
    encrypted_nonce_and_key = gpg.encrypt(
        nonce_and_key, recipients=[recipient_email])
    
    encrypted_comp_signature_and_message = payload
    # create the PGP message
    pgp_message = PGP_MESSAGE.format(
        # Session key component
        recipient_email=recipient_email,
        session_key=str(encrypted_nonce_and_key),

        signature_and_message=encrypted_comp_signature_and_message
    )
    return base64.b64encode(pgp_message.encode('utf-8'))


# Function that receives the message from the server
def receive_message(clientsocket, passphrase):
    # Receive data
    all_data = ""
    count = 0
    try:
        while True:
            data = "" + clientsocket.recv(1024).decode('utf-8')
            if count == 0:
                count += 1
            if not data:
                print("No more data received.")
                break
            all_data += data
            if all_data.endswith("END"):  # Check for the end signal
                all_data = all_data[:-3]  # Remove the end signal from the data
                print("End of data signal received.")
                break
    except Exception as e:
        print(f"Error receiving data: {e}")

    # Split the data into the header and the message
    split_message = all_data.split("/////\n")
    header = split_message[0]
    header_arr = header.split("///")

    sender_certificate = header_arr[1][header_arr[1].find("-----BEGIN PGP SIGNED MESSAGE-----"):] + "///" + header_arr[2]
    sender_public_key = header_arr[2][:header[2].find("\n-----BEGIN PGP SIGNATURE-----")]
    # verify the certificate
    certificate_validity = gpg.verify(sender_certificate)

    ca_signature = header_arr[3][header_arr[3].find(
        "-----BEGIN PGP SIGNED MESSAGE-----"):]

    search_string = "\n-----BEGIN PGP SIGNATURE-----"
    index = ca_signature.find(search_string)
    original_timestamp = ca_signature[(index-92): (index-66)]
    original_timestamp = datetime.datetime.fromisoformat(original_timestamp)

    timestamp_now = datetime.datetime.now()
    # check if the timestamp from the send to arrival time is within 10 seconds
    time_difference = timestamp_now - original_timestamp
    seconds_difference = time_difference.total_seconds()
    time_validity = seconds_difference <= 10
    # verify the signature
    message_data = split_message[1]
    signature_validity = verifySignature(ca_signature, message_data)
    b64_decode_data = (base64.b64decode(message_data))
    final_message_data = b64_decode_data.decode('utf-8')

    # process the message
    safety, messageArray = process_message(final_message_data, passphrase, header, sender_public_key)
    # check if the message is safe to process, meaning the signature is valid, the timestamp is valid, and the certificate is valid
    if safety and signature_validity and time_validity and certificate_validity.valid is True:
        gpg.import_keys(sender_public_key)
        filename = messageArray[0]
        timestamp = messageArray[1]
        caption = messageArray[2]
        image_data = messageArray[3]
        # process image data
        process_image(image_data, filename, timestamp, caption)
        return True, header
    else:
        return False, ""


#  Function that processes the message received from the server
def process_message(d, passphrase, header, sender_public_key):
    sender = header[header.find("SENDER: ")+8:header.find("\nRECIPIENT")]
    # extract the session key and signature and message
    session_key_start = d.index("SESSION_KEY_COMPONENT")
    session_key_end = d.index("\n\nSIGNATURE_AND_MESSAGE")
    session_key_component = d[session_key_start:session_key_end]

    # consists of recip email and session key, in that order
    session_key_component_email = session_key_component[23:session_key_component.index(
        "\n-----BEGIN PGP MESSAGE-----")]
    # session_key_component_session consists of the session key and a nonce
    session_key_component_session = session_key_component[session_key_component.index(
        "-----BEGIN PGP MESSAGE-----"):]
    # extract the signature and message
    signature_and_message_start = d.index("SIGNATURE_AND_MESSAGE")+25
    signature_and_message_component = d[signature_and_message_start:-1]
    signature_and_message_component = base64.b64decode(
        signature_and_message_component)
    # decrypt the session key
    decrypted_session_key = gpg.decrypt(
        session_key_component_session, passphrase=passphrase)

    decrypted_session_key_str = str(decrypted_session_key)
    session_arr = decrypted_session_key_str.split("\n\n")
    # extract the nonce and key
    nonce = session_arr[0][2:-1]
    key = session_arr[1][2:-1]
    # decrypt the signature and message with the session key
    decrypted_signature_and_message = session_decrypt(
        signature_and_message_component, nonce, key)

    # decompress the decrypted signature and message
    decompressed_signature_and_message = decompress(
        decrypted_signature_and_message)
    # split the signature and message
    decompressed_signature_and_message = decompressed_signature_and_message.decode(
    ).split('\n\nMESSAGE: ')
    signature_component = decompressed_signature_and_message[0]
    # split the signature into the timestamp, sender email, and message digest
    signature_array = signature_component.split("///")
    signed_digest = signature_array[1]
    message = decompressed_signature_and_message[1][1:]

    # split message into filename, timestamp, caption, and image data
    messageArray = message.split("\n")
    filename = messageArray[0]
    timestamp = messageArray[1]
    caption = messageArray[2]
    image_data = messageArray[3]
    verification = verifySignature(
        signed_digest, image_data)
    # check if the signature is valid
    if (verification is True):
        return True, messageArray
    return False, []

# Function that verifies authenticity of the sender and message integrity
def verifySignature(signed_digest, image_data):
    # Calculate the hash of the image data
    hashCheck = create_message_digest(image_data)
    # Find the index of the signature in the signed digest
    search_string = "\n-----BEGIN PGP SIGNATURE-----"
    index = signed_digest.find(search_string)
    # Extract the original message digest from the signed digest
    original_message_digest = signed_digest[(index-65): (index-1)]
    # Verify the signature using the signed digest
    verification_result = gpg.verify(signed_digest.encode())
    # Check if the signature is valid and the message digest matches
    if (verification_result.valid and original_message_digest == hashCheck):
        return True
    # Print the verification status and validity if the signature is not valid
    print("STATUS:", verification_result.status)
    print("VALIDITY:", verification_result.valid)
    
    return False


# Function that decodes and saves a received image
def process_image(image_data, filename, timestamp, caption):
    # Decode and save image
    try:
        print("Decoding image data...")
        print("FILENAME: ", filename)
        print("TIMESTAMP: ", timestamp)
        print("CAPTION: ", caption)
        data = image_data
        padded_data = fix_padding(data)
        encoded_again = padded_data.encode('utf-8')
        image_data = base64.b64decode(encoded_again)
    except Exception as e:
        print(f"Failed to decode image data: {e}")
        return

    try:
        print("Saving image...")
        image = Image.open(io.BytesIO(image_data))

        # the filename should be set to the filename of the image but if that name matches an existing file, user can enter their own name
        if os.path.exists(f"./received_images/{filename}.jpg"):
            print("Image with this name already exists.")
            filename = input(
                "Enter the name you wish to save the image as: (Exclude File Extensions!) \n")
            filename = filename + ".jpg"
        else:
            filename = filename + ".jpg"
        image.save(b"./received_images/" +
                   filename.encode('utf-8'), format='JPEG')
        print("Image saved successfully.")
    except Exception as e:
        print(f"Failed to save image: {e}")


# Function that manages a client sending a message
def clientSend(clientsocket, email, passphrase):
    global client_certificate
    print(clientsocket.recv(1024).decode())
    recipient = input()
    clientsocket.send(recipient.encode('utf-8'))
    recipientValidityResponse = clientsocket.recv(1024).decode()
    # check if the recipient is valid
    while recipientValidityResponse == "Recipient not found. Please try again.":
        print(recipientValidityResponse)
        recipient = input()
        if recipient == "Q":
            clientsocket.send(recipient.encode('utf-8'))
            exit()
        else:
            clientsocket.send(recipient.encode('utf-8'))
            recipientValidityResponse = clientsocket.recv(1024).decode()

    recipientPublicKey = clientsocket.recv(
        1024).decode()
    
    sender_public_key = gpg.export_keys(email)
    image_path = input("Enter the path to the image you wish to send: \n")
    file_name = input("Enter the name you wish to send the image as: \n")

    # check that the image exists
    try:
        with Image.open(image_path) as img:
            img.verify()
            print("Image found. Processing...")
    except Exception as e:
        print(f"Image not found: {e}")
        image_path = input("Enter the path to the image you wish to send: \n")
        file_name = input("Enter the name you wish to send the image as: \n")

    caption = input("Enter a caption for the image: \n")
    # create the message to send
    send_request = SEND_REQUEST.format(
        sender=email,
        recipient=recipient,
        timestamp=datetime.datetime.now().isoformat(),
        sender_certificate=client_certificate,
        message=process_message_for_sending(recipient, image_path, email, caption, passphrase, file_name).decode())

    send_message(clientsocket, send_request)

    print(clientsocket.recv(1024).decode())


# Function that manages a client receiving a message
def clientReceive(clientsocket, email, passphrase):
    # Receive response from the server
    response = clientsocket.recv(1024).decode()
    if (response.startswith("No")):
        print(response)
        accessManagement(clientsocket, email, passphrase)
    else:
        while (not (response.strip().startswith("All messages stored"))):
            clientsocket.send(
                "Please send any messages stored".encode('utf-8'))
            clientsocket.recv(1024).decode()
            print("Message " + str(eval(response)+1) +
                  ": \n---------------------------- ")

            clientsocket.send('ACK'.encode('utf-8'))  # send acknowledgement

            # Receive and process the message
            validity, header = receive_message(clientsocket, passphrase)
            if (validity is False):
                print("MESSAGE VERIFICATION FAILED. DELETING MESSAGE.")
                clientsocket.send(
                    "Are there any other messages?".encode('utf-8'))
                response = clientsocket.recv(1024).decode()
            else:
                header_split = (header.split('\n'))
                print("Sender is: " + (header_split[1])[8:])

                print(
                    "Image has been received.\n============================================")
                clientsocket.send(
                    "Are there any other messages?".encode('utf-8'))
                response = clientsocket.recv(1024).decode()
        print(response)
        clientsocket.send("All messages received".encode('utf-8'))


# Function to controls user requests including sending and receiving messages
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


# Function that manages the user menu inlcuding sign up, login and quitting
def userMenu(clientsocket):
    global client_certificate
    while True:
        message = clientsocket.recv(1024)
        print(message.decode('utf-8'))
        option = input()
        clientsocket.send(option.encode('utf-8'))

        if option == "SIGN UP":
            flag = True
            email = input("Please enter your email\n")
            while flag is True:
                if "@" not in email:
                    email = input(
                        "Invalid email. Please enter a valid email\n")
                elif "." not in email[email.find("@"):]:
                    email = input(
                        "Invalid email. Please enter a valid email\n")
                else:
                    flag = False
            clientsocket.send(email.encode('utf-8'))
            isRegistered = clientsocket.recv(1024).decode('utf-8')
            if isRegistered == "True":
                continue
            passphrase = input(
                "Please enter a passphrase. You will need to save this for later!\n").strip()
            # generate key pair
            public_key = generate_key_pair(email, passphrase)
            clientsocket.send(public_key.encode('utf-8'))
            print(
                "SIGN UP SUCCESSFUL! Please reconnect and LOGIN with your new credentials")
            clientsocket.close()
            return

        elif option == "LOGIN":
            email = input("Please enter your email\n")
            while not email.strip():
                print("Email cannot be empty. Please try again.")
                email = input("Please enter your email\n")
            clientsocket.send(email.encode('utf-8'))
            emailResponse = clientsocket.recv(1024).decode()
            while emailResponse != "checking identity...":
                email = input("This user does not exist, please resubmit a valid email:\n")
                while not email.strip():
                    print("Email cannot be empty. Please try again.")
                    email = input("Please enter your email\n")
                clientsocket.send(email.encode('utf-8'))
                emailResponse = clientsocket.recv(1024).decode()
            encryptedNonceToClient = clientsocket.recv(1024).decode()
            passphraseClient = input("Please enter your passphrase\n").strip()

            decryptedNonceClient = gpg.decrypt(
                encryptedNonceToClient, passphrase=passphraseClient, always_trust=True)
            # Send a response to the server (please send public key)
            clientsocket.send("Please send public key".encode('utf-8'))
            # Receieve CA public key here and import to keyring
            ca_public_key = clientsocket.recv(1024).decode()
            gpg.import_keys(ca_public_key)

            encryptedNonceToServer = gpg.encrypt(
                str(decryptedNonceClient), recipients=['CA1@example.com'], always_trust=True)

            clientsocket.send(str(encryptedNonceToServer).encode('utf-8'))
            attemptResponse = clientsocket.recv(1024).decode()
            if attemptResponse == "Login Failure":
                print("Incorrect Passphrase or Public Key. Disconnecting.")
                exit()
            else:
                clientsocket.send("Please send the client certificate".encode('utf-8'))
                client_certificate = clientsocket.recv(1024).decode()
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
