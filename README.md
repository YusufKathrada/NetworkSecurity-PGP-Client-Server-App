# <u> Network and Internetwork Security Assignment </u>



## Overview
This project contains two Python scripts: **'server.py'** and **'client.py'**, each within their respective directories. These scripts work together to create a client-server model, which allows for the sending and receiving of encrypted images and captions, following a PGP-like approach.

## Authors
- **Gregory Maselle**
- **Yusuf Kathrada**
- **Taahir Suleman**

## Prerequisites
Before running the programs, ensure you have the following installed on your system:

1. **Python 3.x**: You can download the latest version of Python from the official [Python website](https://www.python.org/downloads/).
2. **Gpg4win**: Follow the instructions below to download and install Gpg4win.
3. **Required Python Libraries**: The scripts may require additional libraries. You can install them using:
```
pip install python-gnupg Pillow pybase64 pycryptodome
```
Here's what each library is used for:

- <u>python-gnupg</U>: A Python wrapper for the GNU Privacy Guard (GnuPG).
- <u>Pillow</u>: A Python Imaging Library that adds image processing capabilities to your Python interpreter.
- <u>pybase64</u>: A Python library for base64 encoding and decoding.
- <u>pycryptodome</u>: A self-contained Python package of low-level cryptographic primitives.

## Installing Gpg4win
1. **Download Gpg4win**:
- Visit the official Gpg4win [download page](https://www.gpg4win.org/download.html).
- Click on the "Download" button to get the installer.

2. **Install Gpg4win**:
- Run the downloaded installer and follow the on-screen instructions.
- During installation, ensure that GnuPG is selected.

3. **Verify the GPG Binary Path**:
- After installation, ensure that the GPG binary file is saved to the following path: 
```
C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe.
```
- You can check this by navigating to the specified directory in File Explorer and verifying the presence of **'gpg.exe'**.

**Note**: If you are running this program on a non-Windows device, you will need to manually specify the path to the binary file on the **'client.py'** and **'server.py'** files. You will need to edit the following code block in each, such that the gpgbinary points to where **'gpg.exe'** is saved:

```python
# Get the directory of the script
script_dir = os.path.dirname(os.path.abspath(__file__))
gpg_home = os.path.join(script_dir, '.gnupg')
# Create a GPG object
gpg = gnupg.GPG(gnupghome=gpg_home,
                gpgbinary='C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe')
```

4. **Add a configuration file**:
- Via either the *'server'* or the *'client'* directory, inside the *'.gnupg'* folder, you will find a file called **'gpg-agent.conf'**. Copy this file to the following path:

```
...\AppData\Roaming\gnupg
```
The configuration file ensures that passphrases are not cached, which could lead to incorrect handling of passphrase entries.

## Running the Server
1. Navigate to the directory containing **'server.py'**.
2. Run the server script using the following command:

```
python server.py
```
The server will start and listen for incoming connections.

## Running the Client
1. Navigate to the directory containing **'client.py'**.
2. Run the client script using the following command:
```
python client.py
```
The client will connect to the server and initiate communication.


## Usage
1. **Start the server**:

    Ensure the server is running before starting the client.

2. **Start the client**:

    Run the client script to connect to the server. Follow any prompts or instructions provided by the client script to communicate with the server.

## Troubleshooting
- **Connection Issues**: Ensure both scripts are running on the same network and the server is accessible.

- **Firewall Settings**: Check your firewall settings to ensure they are not blocking the communication ports used by the server and client.

## License
This project is licensed under the MIT License.