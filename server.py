#!/usr/bin/python

import socket
import threading
import time


#HOST = socket.gethostname()
HOST =  '192.168.1.97'
PORT = 7031

def receive_from_client(clientsocket, addr):

    while True:
        msg = clientsocket.recv(1024)
        print addr, ' >> ', msg

    clientsocket.close()

def send_to_client(clientsocket, addr):

    while True:

        time.sleep(10)
        msg = 'POLL\x00\x00\x00\x00'
        print 'Polling Status of ', addr
        clientsocket.send(msg)

    clientsocket.close()

s = socket.socket()

print 'Server started!'
print 'Waiting for clients...'

s.bind((HOST, PORT))
s.listen(5)

while True:
    c, addr = s.accept()
    print 'Got connection from', addr

    # Multi-Threading
    sender = threading.Thread(target=receive_from_client, args=(c, addr))
    recver = threading.Thread(target=send_to_client, args=(c, addr))

    # Set as deamons so they die when main thread exits
    sender.daemon = True
    recver.daemon = True

    # Run Daemons (Threads)
    sender.start()
    recver.start()


s.close()

