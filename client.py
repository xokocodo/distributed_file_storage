import socket
import binascii
import time
import threading
import select
import atexit
import hashlib
import struct
import yaml
import os

from variables import *

USER_ID = '\x00\x00\x00\x00\x00\x00\x13\x37'
PASSWORD = 'hunter2'
KEY = binascii.unhexlify(hashlib.sha256(PASSWORD).hexdigest())

class FileObject:

    def __init__(self, chunk_len, hash):
        self.chunk_len = chunk_len
        self.hash = hash

        self.chunks = ['' for x in range(chunk_len)]

    def addChunk(self, chunk_num, data):
        self.chunks[chunk_num] = data

    def finalize(self):
        return "".join(self.chunks)


class ClientConnectionHandler:

    def __init__(self, sock, client):
        self.sock = sock
        self.send_lock = threading.Lock()
        self.closed = False
        self.client = client
        self.f_obj = None

    def send(self, msg):
        with self.send_lock:
            msg_len = struct.pack('!I', len(msg))
            self.sock.sendall(PROTOCOL_HEADER + msg_len + msg)

    def run(self):

        # Connect to Server
        try:
            self.sock.connect((SERVER_ADDRESS, PORT))
        except socket.error:
            log('Server Not Available')
            return

        log('Connected to Server')

        self.client.socket_ready.set()

        # Authenticate with Server
        # Max Retries = 3
        for i in range(3):

            # Send Connect Message
            self.send(CONNECT + USER_ID + KEY)

            # Wait for Response from Server
            try:
                header = self.sock.recv(4)
                if header != PROTOCOL_HEADER:
                    break
                msg_len = self.sock.recv(4)
                msg_len_int = struct.unpack('!I', msg_len)[0]

                raw_data = self.sock.recv(msg_len_int)
            except socket.error:
                self.closed = True
                log('Server Disconnected.')
                break

            log('Raw Data: %s' % raw_data)
            log('Hexlified Data: %s' % binascii.hexlify(raw_data))

            # Connection Was Closed
            if raw_data == '':
                log('Connection with server was closed.')
                self.closed = True
                break

            # Parse out msg type
            msg_type = raw_data[:8]

            if msg_type == CONNECT_SUCESS:
                log('Successfully Authenticated with Server')
                break

        # Start Receiving
        self.receive()

    def receive(self):

        while True:

            # Connection Closed
            if self.closed:
                break

            try:
                header = self.sock.recv(4)
                if header != PROTOCOL_HEADER:
                    break
                msg_len = self.sock.recv(4)
                msg_len_int = struct.unpack('!I', msg_len)[0]

                raw_data = self.sock.recv(msg_len_int)
            except socket.error:
                self.closed = True
                log('Disconnected')
                break
            except KeyboardInterrupt:
                log('Closing Connection and Exiting.')
                break

            log('Raw Data: %s' % raw_data)
            log('Hexlified Data: %s' % binascii.hexlify(raw_data))

            # Connection Was Closed
            if raw_data == '':
                log('Connection with server was closed.')
                self.closed = True
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                    self.sock.close()
                except socket.error:
                    pass
                break

            # Parse out msg type
            msg_type = raw_data[:8]

            # msg type switch case
            fn = {
                POLL: lambda: self.poll(raw_data[8:]),
                PONG: lambda: self.pong(),
                FORMAT_FAILURE: lambda: self.bad_message(),
                UNKOWN_MSG_RECV: lambda: self.unknown_message(),
                FILE_DELETE_GOOD: lambda : self.file_delete_response(msg_type),
                FILE_DELETE_BAD_AUTH: lambda: self.file_delete_response(msg_type),
                FILE_DELETE_BAD_OWNER: lambda: self.file_delete_response(msg_type),
                FILE_DELETE_BAD_UID: lambda: self.file_delete_response(msg_type),
                FILE_GET_BAD_UID: lambda: self.file_get_response(msg_type),
                FILE_GOOD: lambda: self.file_storage_response(msg_type),
                FILE_BAD_HASH: lambda: self.file_storage_response(msg_type),
                FILE_BAD_UID: lambda: self.file_storage_response(msg_type),
                FILE_BAD_SEQ: lambda: self.file_storage_response(msg_type),
                FILE_START: lambda: self.start_file(raw_data[8:]),
                FILE_END: lambda: self.end_file(raw_data[8:]),
                FILE_DATA: lambda: self.file_data(raw_data[8:]),
            }.get(msg_type)

            if fn is not None:
                # Run the Message Handler
                fn()
            else:
                log('Unknown Message Type Received')
                log('Message Type = %s' % msg_type)
                self.send(UNKOWN_MSG_RECV)

    def bad_message(self):
        log('Server Could Not Parse Last Message')

    def unknown_message(self):
        log('Server Did Not Recognize Last Message')

    def pong(self):
        log('Received Pong Signal')

    def file_delete_response(self, response_type):
        if response_type == FILE_DELETE_GOOD:
            log('File Deleted Successfully')
        elif response_type == FILE_DELETE_BAD_UID:
            log('File With That UID Not Found')
        elif response_type == FILE_DELETE_BAD_OWNER:
            log('Not Authorized to Delete File')
        elif response_type == FILE_DELETE_BAD_AUTH:
            log('Failed to Authenticate to Delete File')
        else:
            log('Unknown File Delete Failure')

    def file_storage_response(self, response_type):
        if response_type == FILE_GOOD:
            log('File Stored Successfully')
        elif response_type == FILE_BAD_HASH:
            log('File Hash Did Not Match')
        elif response_type == FILE_BAD_SEQ:
            log('File Storage Out of Sequence')
        elif response_type == FILE_BAD_UID:
            log('File At Start Did Not Match File At End')
        else:
            log('Unknown File Storage Failure')

    def file_get_response(self, response_type):
        if response_type == FILE_GET_BAD_UID:
            log('Unable To Get File. No File with That UID.')
        else:
            log('Unknown Get File Failure')

    def ping(self):
        self.send(PING)
        log('Sent Ping Signal')

    def poll(self, data):

        log('Poll')

        # Parse out Fields
        try:
            poll_id = data[0:8]
            if len(poll_id) != 8:
                raise IndexError
        except IndexError:
            log('Invalid Data Format')
            log('Sending Format Failure Message to')
            self.send(FORMAT_FAILURE)
            return

        log('Poll ID: %d' % struct.unpack('!Q', poll_id)[0])

        msg = STATUS_GOOD + poll_id
        self.send(msg)
        log('Sent Status Good Signal')

    def send_raw(self, data):
        self.send(data)
        log('Sent Raw Data: %s' % data)

    def save_file(self, file_data):

        log('Save File')

        log('File Data: %s' % binascii.hexlify(file_data))

        # Break File Up Into Chunks
        chunks = [file_data[i:i + 1024] for i in range(0, len(file_data), 1024)]

        log('# Of Chunks: %s' % len(chunks))

        # Get File Hash
        file_hash = binascii.unhexlify(hashlib.sha256(file_data).hexdigest())

        log('File Hash: %s' % binascii.hexlify(file_hash))

        # Send File Start
        msg = FILE_START + struct.pack('!Q', len(chunks)) + file_hash
        log('Sending File Start Message')
        self.send(msg)

        # Send File Data
        for i, chunk in enumerate(chunks):
            msg = FILE_DATA + file_hash + struct.pack('!Q', i) + chunk
            log('Sending File Data Message')
            self.send(msg)

        # Send File End
        msg = FILE_END + file_hash
        log('Sending File End Message')
        self.send(msg)

    def get_file(self, file_uid):
        log('Sending File Get Request for UID %s' % file_uid)

        msg = FILE_GET_REQUEST + binascii.unhexlify(file_uid)
        self.send(msg)

    def delete_file(self, file_uid):
        log('Sending File Delete Request for UID %s' % file_uid)
        msg = FILE_DELETE + binascii.unhexlify(file_uid) + KEY
        self.send(msg)

    def start_file(self, data):

        log('Start of File')

        # Parse out Fields
        try:
            chunks = data[0:8]
            hash = data[8:40]
        except IndexError:
            log('Invalid Data Format')
            log('Sending Format Failure Message to')
            self.send(FORMAT_FAILURE)
            return

        # Unfinished File Object Already
        if self.f_obj is not None:
            log('Overwriting File Object')

        self.f_obj = FileObject(chunks, hash)

    def file_data(self, data):

        log('File Data')

        if self.f_obj is None:
            log('No File Object')
            log('Sending Bad File Sequence Message')
            self.send(FILE_BAD_SEQ)
            return

        try:
            hash = data[:32]
            chunk_num = data[32:40]
            file_data = data[40:]
        except IndexError:
            log('%s :: Invalid Data Format')
            log('Sending Format Failure Message to %s')
            self.send(FORMAT_FAILURE)
            return

        self.f_obj.addChunk(file_data)

    def end_file(self, data):

        log('End of File')

        if self.f_obj is None:
            log('No File Object')
            return

        try:
            hash = data[:32]
        except IndexError:
            log('Invalid End of File Format')
            log('Sending Format Failure Message')
            self.send(FORMAT_FAILURE)
            return

        # Check Hash (as UID)
        if hash != self.f_obj.hash:
            log('Bad UID for File End')
            log('Sending Bad UID Message')
            self.send(FILE_BAD_UID)
            return

        # Get Full File
        full_data = self.f_obj.finalize()
        log('Full Data: \n%s' % binascii.hexlify(full_data))

        # Verify Hash
        hash_recvd = binascii.unhexlify(hashlib.sha256(full_data).hexdigest())
        hash_expected = self.f_obj.hash
        log('Hash Received: %s' % binascii.hexlify(hash_recvd))
        log('Hash Expected: %s' % binascii.hexlify(hash_expected))

        if hash_recvd != hash_expected:
            log('Sending Bad Hash Message')
            self.send(FILE_BAD_HASH)
        else:

            client.save(full_data)

            # Send File Good
            log('Sending File Good Message to %s')
            self.send(FILE_GOOD)

        # Close File Object
        self.f_obj = None


class FileStorageClient:

    def __init__(self):

        # Create Client Socket
        self.sock = socket.socket()

        self.connection_handler = ClientConnectionHandler(self.sock, self)

        self.socket_ready = threading.Event()

    def run(self):
        log('Client Started')

        # Multi-Threading
        cli_thread = threading.Thread(target=self.run_cli)

        # Set as daemons so they die when main thread exits
        cli_thread.daemon = True

        # Run daemons (threads)
        cli_thread.start()

        # Run Connection Handler
        self.connection_handler.run()

    def run_cli(self):

        self.socket_ready.wait()

        log('Running Command Line Interface')

        while True:
            menu_items = ['1', '2', '3', '4', '5']

            print('Client Menu')
            print('1. Ping Server')
            print('2. Send Arbitrary Data')
            print('3. Save File')
            print('4. Get File')
            print('5. Delete File')

            opt = raw_input('Please Select an Option: \n')
            if opt in menu_items:
                {
                    '1': lambda: self.connection_handler.ping(),
                    '2': lambda: self.send_raw(raw_input('Enter (Hexlified) Data to Send:')),
                    '3': lambda: self.save_file(raw_input('Enter file path to save:')),
                    '4': lambda: self.get_file(raw_input('Enter file uid to get:')),
                    '5': lambda: self.delete_file(raw_input('Enter file uid to delete:')),
                }[opt]()
            else:
                print 'Not a valid choice.'

    def send_raw(self, data):
        try:
            unhexlified_data = binascii.unhexlify(data)
        except TypeError:
            log('Failed to Unhexlify Data')
            return
        self.connection_handler.send_raw(unhexlified_data)

    def save_file(self, file_path):
        try:
            # Read Data
            with open(file_path, 'r') as f:
                file_data = f.read()

        except IOError:
            log('Invalid File Path')
            return

        decrypted_hash = hashlib.sha256(file_data).hexdigest()

        # Create Key
        key = AESCipher.get_key()
        iv = AESCipher.get_iv()

        # Encrypt Data
        aes_obj = AESCipher(key)
        enc_data = aes_obj.encrypt(file_data, iv)
        encrypted_hash = hashlib.sha256(enc_data).hexdigest()

        # Sanity Check Decrypt
        dec_data = aes_obj.decrypt(enc_data, iv)
        log('Encrypted Data: %s' % binascii.hexlify(enc_data))
        log('Decrypted Data: %s' % binascii.hexlify(dec_data))
        if dec_data != enc_data:
            log('Loopback Encrypt/Decrypt Failed')
            #3return

        # Save Key and IV to Folder
        key_file_data = {
            'key' : key,
            'iv': iv,
            'encrypted_hash': encrypted_hash,
            'decrypted_hash': decrypted_hash,
            'file_name': os.path.basename(file_path),
        }

        # Write to File in Key Folder
        key_file = CLIENT_KEY_FOLDER + encrypted_hash + '.yaml'
        with open(key_file, 'w') as outfile:
            yaml.dump(key_file_data, outfile)

        # Send Encrypted Data
        self.connection_handler.save_file(enc_data)

    def get_file(self, file_uid):
        log('Entered UID: %s' % file_uid)
        try:
            uid_int = int(file_uid, 16)
            if len(file_uid) != 24:
                log('Invalid File UID - Bad Length')
                return
            else:
                self.connection_handler.get_file(file_uid)
        except ValueError:
            log('Invalid File UID - Bad Parse')

    def delete_file(self, file_uid):
        log('Entered UID: %s' % file_uid)
        try:
            uid_int = int(file_uid, 16)
            if len(file_uid) != 24:
                log('Invalid File UID - Bad Length')
                return
            else:
                self.connection_handler.delete_file(file_uid)

        except ValueError:
            log('Invalid File UID - Bad Parse')

    def save(self, file_data):

        file_hash = hashlib.sha256(file_data).hexdigest()

        key_file_path = CLIENT_KEY_FOLDER + file_hash + '.yaml'

        if not os.path.exists(key_file_path):
            log('Key For File Does Not Exist')
            return

        with open(key_file_path, 'r') as ymlfile:
            key_file_data = yaml.load(ymlfile)

        # Get Key and IV
        key = key_file_data['key']
        iv = key_file_data['iv']

        # Decrypt Data
        aes_obj = AESCipher(key)
        dec_data = aes_obj.encrypt(file_data, iv)
        decrypted_hash = hashlib.sha256(dec_data).hexdigest()

        # Check Decryption
        if decrypted_hash != key_file_data['decrypted_hash']:
            log('Decryption Failure')
            return

        # Save File
        dst_file = CLIENT_FILE_DESTINATION_FOLDER + key_file_data['file_name']
        with open(dst_file, 'w') as f:
            f.write(dec_data)

    def exit(self):

        log('Safely Exiting Client')
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        log('Closed Client Socket')


if __name__ == '__main__':

    client = FileStorageClient()

    # Register Exit handler
    #atexit.register(client.exit)

    client.run()