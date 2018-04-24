#!/usr/bin/python

import socket
import threading
import time
import binascii

#HOST = socket.gethostname()
HOST =  '192.168.1.97'
PORT = 7031

FILE_START = 'F_START\x00'
FILE_END = 'F_END\x00\x00\x00'
FILE_DATA = 'F_DATA\x00\x00'
STATUS_GOOD = 'GOOD\x00\x00\x00\x00'

file_objs = {}

class fileObject:

    def __init__(self, uid, chunk_len, hash):
        self.uid = uid
        self.chunk_len = chunk_len
        self.hash = hash

        self.chunks = ['' for x in range(chunk_len)]

    def addChunk(self, chunk_num, data):
        self.chunks[chunk_num] = data

    def finalize(self):
        return "".join(self.chunks)


def start_file(data):

    uid = data[:8]
    chunks = data[8:16]
    hash = data[16:48]

    # Check if UID is Already in List

    file_objs[uid] = fileObject(uid, chunks, hash)

def file_data(data):


    uid = data[:8]
    chunk_num = data[8:16]
    file_data = data[16:]

    file_objs[uid].addChunk(chunk_num, file_data)

def end_file(data):

    uid = data[:8]
    full_data = file_objs[uid].finalize()

    # Verify Hash

    # Send Good / Bas

    # Save Data

    print binascii.hexlify(full_data)


def status_good():
    print 'Status Good'

def receive_from_client(clientsocket, addr):

    while True:
        raw_data = clientsocket.recv(1024)
        print addr, ' >> ', raw_data
        print addr, ' >> ', binascii.hexlify(raw_data)

        if raw_data == '':
            break  # no more data

        # Parse out msg type
        msg_type = raw_data[:8]

        # msg type switch case
        fn = {
            FILE_START: lambda: start_file(raw_data[8:]),
            FILE_END: lambda: end_file(raw_data[8:]),
            FILE_DATA: lambda: file_data(raw_data[8:]),
            STATUS_GOOD: lambda: status_good(),
        }.get(msg_type)

        fn()

        time.sleep(1)


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

