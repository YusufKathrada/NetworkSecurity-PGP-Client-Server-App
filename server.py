import socket

#Creating the socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "0.0.0.0"
port = 1200 

#Binding to socket
serversocket.bind((host, port))

#Starting TCP listener
serversocket.listen(3)

while True:
    #Starting the connection 
    clientsocket,address = serversocket.accept()

    print("received connection from " + str(address))
    
    #Message sent to client after successful connection
    message = 'Hello! Thank you for connecting to the server' + "\r\n"
    
    clientsocket.send(message.encode('utf-8'))

    clientsocket.close()
# Test