import socket

#Create socket object
clientsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#host = "0.0.0.0"
host = socket.gethostname()

port = 1200

clientsocket.connect((host, port)) #You can substitue the host with the server IP

#Receiving a maximum of 1024 bytes
message = clientsocket.recv(1024)

clientsocket.close()

print(message.decode('utf-8'))
# Test