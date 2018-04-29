#!/usr/bin/python
import os
import socket
import threading
import time
import binascii
import atexit
import hashlib
import struct
from pymongo import MongoClient
from bson.objectid import ObjectId

from variables import *


class FileObject:

    def __init__(self, chunk_len, hash):
        self.chunk_len = chunk_len
        self.hash = hash

        self.chunks = ['' for x in range(chunk_len)]

    def addChunk(self, chunk_num, data):
        self.chunks[chunk_num] = data

    def finalize(self):
        return "".join(self.chunks)


class ServerConnectionHandler:

    def __init__(self, con_obj, addr, port, server):
        self.c = con_obj
        self.address = addr
        self.port = port
        self.send_lock = threading.Lock()
        self.closed = False
        self.f_obj = None

        self.user_id = None
        self.hashed_key = None

        self.poll_id = None

        self.server = server

        self.file_status = None

        self.file_event = threading.Event()


    def run(self):

        # Authenticate First
        while True:

            # Wait for Application Layer Connection
            # Authenticate Client
            try:
                header = self.c.recv(4)
                if header != PROTOCOL_HEADER:
                    break
                msg_len = self.c.recv(4)
                msg_len_int = struct.unpack('!I', msg_len)[0]

                raw_data = self.c.recv(msg_len_int)
            except socket.error:
                self.closed = True
                log('Server Disconnected.')
                break

            log('Received Message from %s' % self.address)
            log('Raw Data: %s' % raw_data)
            log('Hexlified Data: %s' % binascii.hexlify(raw_data))

            # Connection Was Closed
            if raw_data == '':
                log('Connection with %s was closed.' % self.address)
                self.closed = True
                self.c.shutdown(socket.SHUT_RDWR)
                self.c.close()
                break

            # Parse out msg type
            msg_type = raw_data[:8]

            if msg_type != CONNECT:
                log('%s :: Unexpected Message Type Received')
                self.send(UNKOWN_MSG_RECV)
                break
            else:
                try:
                    user_id = raw_data[8:16]
                    key = raw_data[16:48]
                except IndexError:
                    log('%s :: Invalid Message Data')
                    with self.send_lock:
                        msg = FORMAT_FAILURE
                        log('Sending Format Failure Message to %s' % self.address)
                        self.c.send(msg)
                    break

                hashed_key = binascii.unhexlify(hashlib.sha256(key).hexdigest())

            if server.verify_user(binascii.hexlify(user_id), binascii.hexlify(hashed_key)):
                self.user_id = user_id
                self.hashed_key = hashed_key
                log('%s :: Authenicated as User %s' % (self.address, binascii.hexlify(user_id)))
                log('Sending Good Authentication Message to %s' % self.address)
                self.send(CONNECT_SUCESS)
                break
            else:
                log('%s :: Authenication Failed')
                log('Sending Bad Authentication Message to %s' % self.address)
                self.send(CONNECT_FAIL_AUTH)


        # Multi-Threading
        receiver = threading.Thread(target=self.receive)
        poller = threading.Thread(target=self.poll)

        # Set as deamons so they die when main thread exits
        receiver.daemon = True
        poller.daemon = True

        # Run Daemons (Threads)
        receiver.start()
        poller.start()

    def send(self, msg):
        with self.send_lock:
            msg_len = struct.pack('!I', len(msg))
            self.c.sendall(PROTOCOL_HEADER + msg_len + msg)

    def poll(self):

        self.poll_id = 0

        while True:

            # Connection Closed
            if self.closed:
                break

            self.poll_id += 1
            log('%s :: Polling Status' % self.address)
            msg = POLL + struct.pack('!Q', self.poll_id)
            self.send(msg)

            # Wait Between Polling Messages
            time.sleep(60)

    def receive(self):

        while True:

            # Connection Closed
            if self.closed:
                break

            try:
                header = self.c.recv(4)
                if header != PROTOCOL_HEADER:
                    break
                msg_len = self.c.recv(4)
                msg_len_int = struct.unpack('!I', msg_len)[0]

                raw_data = self.c.recv(msg_len_int)
            except socket.error:
                self.closed = True
                log('Client Disconnected.')
                break

            log('Received Message from %s' % self.address)
            log('Raw Data: %s' % raw_data)
            log('Hexlified Data: %s' % binascii.hexlify(raw_data))

            # Connection Was Closed
            if raw_data == '':
                log('Connection with %s was closed.' % self.address)
                self.closed = True
                try:
                    self.c.shutdown(socket.SHUT_RDWR)
                    self.c.close()
                except socket.error:
                    pass
                break

            # Parse out msg type
            msg_type = raw_data[:8]

            # msg type switch case
            fn = {
                FILE_START: lambda: self.start_file(raw_data[8:]),
                FILE_END: lambda: self.end_file(raw_data[8:]),
                FILE_DATA: lambda: self.file_data(raw_data[8:]),
                FILE_GOOD: lambda: self.file_good(raw_data[8:]),
                STATUS_GOOD: lambda: self.status_good(raw_data[8:]),
                STATUS_BAD: lambda: self.status_bad(raw_data[8:]),
                FILE_GET_REQUEST: lambda: self.get_file(raw_data[8:]),
                FILE_GOOD: lambda: self.set_file_status(FILE_GOOD),
                FILE_BAD_HASH: lambda: self.set_file_status(FILE_BAD_HASH),
                FILE_BAD_UID: lambda: self.set_file_status(FILE_BAD_UID),
                FILE_DELETE: lambda: self.delete_file(raw_data[8:]),
                PING: lambda: self.ping(raw_data[8:]),
                FORMAT_FAILURE: lambda: self.bad_message(raw_data[8:]),
                UNKOWN_MSG_RECV: lambda: self.unknown_message(raw_data[8:]),
            }.get(msg_type)

            if fn is not None:
                # Run the Message Handler
                fn()
            else:
                log('%s :: Unknown Message Type Received')
                self.send(UNKOWN_MSG_RECV)

    def bad_message(self, data):
        log('%s :: Client Could Not Parse Last Message')

    def unknown_message(self, data):
        log('%s :: Client Did Not Recognize Last Message')

    def ping(self, data):
        log('%s :: Ping' % self.address)
        log('Sending Pong Message to %s' % self.address)
        self.send(PONG)

    def set_file_status(self, status):
        self.file_status = status
        self.file_event.set()

    def file_good(self, data):
        log('%s :: File Good' % self.address)

    def start_file(self, data):

        log('%s :: Start of File' % self.address)

        # Parse out Fields
        try:
            chunks = data[0:8]
            hash = data[8:40]
        except IndexError:
            log('%s :: Invalid Data Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        # Unfinished File Object Already
        if self.f_obj is not None:
            log('%s :: Overwriting File Object' % self.address)

        chunks_int = struct.unpack('!Q', chunks)[0]

        log('%s :: # Of Chunks = %d' % (self.address, chunks_int))

        self.f_obj = FileObject(chunks_int, hash)

    def file_data(self, data):

        log('%s :: File Data' % self.address)

        if self.f_obj is None:
            log('%s :: No File Object' % self.address)
            log('Sending Bad File Sequence Message to %s' % self.address)
            self.send(FILE_BAD_SEQ)
            return

        try:
            hash = data[:32]
            chunk_num = data[32:40]
            file_data = data[40:]
        except IndexError:
            log('%s :: Invalid Data Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        chunk_num_int = struct.unpack('!Q', chunk_num)[0]

        self.f_obj.addChunk(chunk_num_int, file_data)

    def end_file(self, data):

        log('%s :: End of File' % self.address)

        if self.f_obj is None:
            log('%s :: No File Object' % self.address)
            return

        try:
            hash = data[:32]
        except IndexError:
            log('%s :: Invalid End of File Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        # Check Hash (as UID)
        if hash != self.f_obj.hash:
            log('%s :: Bad UID for File End' % self.address)
            log('Sending Bad UID Message to %s' % self.address)
            self.send(FILE_BAD_UID)
            return

        # Get Full File
        full_data = self.f_obj.finalize()
        log('%s :: Full Data: \n%s' % (self.address, binascii.hexlify(full_data)))

        # Verify Hash
        hash_recvd = binascii.unhexlify(hashlib.sha256(full_data).hexdigest())
        hash_expected = self.f_obj.hash
        log('%s :: Hash Received: %s' % (binascii.hexlify(hash_recvd), self.address))
        log('%s :: Hash Expected: %s' % (binascii.hexlify(hash_expected), self.address))

        if hash_recvd != hash_expected:
            log('Sending Bad Hash Message to %s' % self.address)
            self.send(FILE_BAD_HASH)
        else:
            uid = self.server.save_file(full_data, self.user_id)
            uid = binascii.unhexlify(str(uid))

            # Send File Good
            log('Sending File Good Message to %s' % self.address)
            self.send(FILE_GOOD + uid)

        # Close File Object
        self.f_obj = None

    def get_file(self, data):
        log('%s :: Get File' % self.address)

        try:
            uid = data[:12]
        except IndexError:
            log('%s :: Invalid Get File Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        # Retrieve File Data
        file_data = server.get_file(uid)

        # Check if File is Valid
        if file_data is None:
            log('%s :: Invalid File UID' % self.address)
            log('Sending Bad UID Message to %s' % self.address)
            self.c.send(FILE_GET_BAD_UID)
            return

        # Break File Up Into Chunks
        chunks = [file_data[i:i + 1024] for i in range(0, len(file_data), 1024)]

        # Get File Hash
        file_hash = binascii.unhexlify(hashlib.sha256(file_data).hexdigest())

        # Clear File Status
        self.file_status = None

        # Retry Max of 3 Times
        for i in range(3):

            # Send File Start
            msg = FILE_START + struct.pack('!Q', len(chunks)) + file_hash
            log('Sending File Start Message to %s' % self.address)
            self.send(msg)

            # Send File Data
            for i, chunk in enumerate(chunks):
                with self.send_lock:
                    msg = FILE_START + file_hash + struct.pack('!Q', i) + chunk
                    log('Sending File Data Message to %s' % self.address)
                    self.c.send(msg)

            # Send File End
            msg = FILE_END + file_hash
            log('Sending File End Message to %s' % self.address)
            self.send(msg)

            # Wait for Success
            self.file_event.wait(timeout=60)
            if self.file_status == FILE_GOOD:
                break
            self.file_event.clear()

    def delete_file(self, data):
        log('%s :: Delete File' % self.address)

        try:
            uid = data[:12]
            key = data[12:44]
        except IndexError:
            log('%s :: Invalid Delete File Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.c.send(FORMAT_FAILURE)
            return

        owner = server.get_owner(uid)

        # Check File ID
        if owner is None:
            log('%s :: File Does Not Exist' % self.address)
            log('Sending Bad File ID Message to %s' % self.address)
            self.send(FILE_DELETE_BAD_UID)
            return

        # Verify Ownership
        if owner != self.user_id:
            log('%s :: Cannot Delete - User is Not Owner')
            log('Sending Bad Ownder Message to %s' % self.address)
            self.send(FILE_DELETE_BAD_OWNER)
            return

        # Hash Key
        hashed_key = binascii.unhexlify(hashlib.sha256(key).hexdigest())

        # Verify Key Authentication
        if not server.verify_user(binascii.hexlify(self.user_id), binascii.hexlify(hashed_key)):
            log('%s :: Authenication Failed')
            log('Sending Bad Authentication Message to %s' % self.address)
            self.send(FILE_DELETE_BAD_AUTH)
            return

        log('%s :: Authenicated as User %s' % (self.address, binascii.hexlify(self.user_id)))

        # Delete File
        self.server.delete_file(uid)

        log('%s :: File Deleted' % self.address)
        log('Sending File Deleted Message to %s' % self.address)
        self.send(FILE_DELETE_GOOD)


    def status_good(self, data):
        log('%s :: Status Good' % self.address)

        try:
            poll_id_recv = data[:8]
            if len(poll_id_recv) != 8:
                raise IndexError
        except IndexError:
            log('%s :: Invalid Status Good Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        poll_id_recv_int = struct.unpack('!Q', poll_id_recv)[0]

        log('%s :: Poll ID = %d' % (self.address, poll_id_recv_int))

        if self.poll_id != poll_id_recv_int:
            log('%s :: Missed Polling Cycle' % self.address)

    def status_bad(self, data):
        log('%s :: Status Bad' % self.address)

        try:
            poll_id_recv = data[:8]
            if len(poll_id_recv) != 8:
                raise IndexError
        except IndexError:
            log('%s :: Invalid Status Bad Format' % self.address)
            log('Sending Format Failure Message to %s' % self.address)
            self.send(FORMAT_FAILURE)
            return

        log('%s :: Poll ID = %d' % struct.unpack('!Q', poll_id_recv)[0])

        if self.poll_id != poll_id_recv:
            log('%s :: Missed Polling Cycle' % self.address)


class FileStorageServer:

    def __init__(self):

        # Create Server Socket
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        log('Server started!')
        log('Waiting for clients...')

        # Bind Socket to Port
        self.sock.bind((HOST, PORT))
        self.sock.listen(5)

        # Create List of Connection Handlers
        self.connection_handlers = []

        # Connect To DB
        self.mongo_client = MongoClient('mongodb://localhost:27017')
        self.db = self.mongo_client['distributed_file_system']

    def run(self):

        # Listen and Wait
        while True:
            # Wait for Connection
            try:
                c, addr_port = self.sock.accept()
            except socket.error:
                log('Failed To Accept Connection')
            except KeyboardInterrupt:
                log('Received KeyboardInterrupt. Closing.')
                break

            addr = addr_port[0]
            port = addr_port[1]
            log('Got connection from %s' % addr)

            # Create Connection Handler Instance and Hand Off
            ch = ServerConnectionHandler(c, addr, port, self)
            self.connection_handlers.append(ch)
            ch.run()

    def exit(self):
        log('Safely Exiting Server')
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except socket.error:
            pass

        log('Closed Server Socket')

        for h in self.connection_handlers:
            h.c.shutdown(socket.SHUT_RDWR)
            h.c.close()
            log('Closed Client Connection: %s' % h.address)

        log('All Connections Closed. Exiting')

    def save_file(self, file_data, user_id):

        file_hash = binascii.unhexlify(hashlib.sha256(file_data).hexdigest())

        # Save File
        file_location = SERVER_FILE_DESTINATION_FOLDER + binascii.hexlify(file_hash) + '.dat'
        with open(file_location, 'w') as f:
            f.write(file_data)

        file_data = {'file_location': file_location, 'user_id': user_id}
        result = self.db.files.insert_one(file_data)
        log('Added File to DB. DB ID: %s' % result.inserted_id)

        return result.inserted_id

    def get_owner(self, file_uid):

        file = self.db.users.find_one({'_id': ObjectId(binascii.hexlify(file_uid)) })

        if file is None:
            log('File ID %s Not Found' % file_uid)
            return None

        return file.user_id

    def get_file(self, file_uid):

        file = self.db.users.find_one({'_id': ObjectId(binascii.hexlify(file_uid)) })

        if file is None:
            log('File ID %s Not Found' % file_uid)
            return None

        file_location =  file.file_location

        # Open File and Get Data
        with open(file_location, 'r') as f:
            data = f.read()

        return data

    def delete_file(self, file_uid):

        file = self.db.users.find_one({'_id': ObjectId(binascii.hexlify(file_uid))})

        if file is None:
            log('File ID %d Not Found' % binascii.hexlify(file_uid))
            return None

        file_location =  file.file_location

        # Delete File
        os.remove(file_location)

        # Remove from DB
        self.db.files.remove({"file_uid": file_uid})

    def verify_user(self, user_id, hashed_key):

        user = self.db.users.find_one({'user_id': user_id})

        log('User in DB: %s' % user)

        # New User
        if user is None:
            log('User ID 0x%s Does Not Exist' % user_id)

            user_data = {'user_id' : user_id, 'hashed_key': hashed_key}
            result = self.db.users.insert_one(user_data)
            log('Added User to DB. DB ID: %s' % result.inserted_id)

            return True

        if user[u'hashed_key'] != hashed_key:
            log('Invalid Authentication Key for User ID 0x%s' % user_id)
            return False

        return True

if __name__ == '__main__':

    server = FileStorageServer()

    # Register Exit handler
    atexit.register(server.exit)

    server.run()
