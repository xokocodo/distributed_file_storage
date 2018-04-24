import socket
import binascii
import time
import threading
import select

SERVER_ADDRESS = '68.6.174.164'
#SERVER_ADDRESS = '192.168.1.97'

PORT = 7031

CONNECT = 'CONNECT\x00'
POLL = 'POLL\x00\x00\x00\x00'
PING = 'PING\x00\x00\x00\x00'
START_FILE = 'F_START\x00'
END_FILE = 'F_END\x00'

STATUS_GOOD = 'GOOD\x00\x00\x00\x00'

class ServerConnection:

    def __init__(self):

        self.s = socket.socket()
        self.s.connect((SERVER_ADDRESS, PORT))

    def open(self):
        self.s.send(CONNECT)
        print 'Sent Connect Signal'

    def close(self):
        self.s.close()

    def poll(self):
        self.s.send(STATUS_GOOD)
        print 'Sent Status Good Signal'

    def ping(self):
        self.s.send(PING)
        print 'Sent Ping Signal'

    def send_raw(self, data):
        self.s.send(data)
        print 'Sent Raw Data: %s' % data

    def save_file(self, file_path):
        self.s.send(START_FILE)
        self.s.send('\x00' * 8 + '\x00' * 7 + '\x04' + '\x00' * 32)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(128), b""):
               self.s.send(chunk)
        self.s.send(END_FILE)

class KeyStore:

    def __init__(self):
        pass

class LocalStorageManager:

    def __init__(self):
        pass


class ClientManager:

    def __init__(self):
        pass

    def save(self, local_file_path):
        pass

    def get(self, file_uid):
        pass


# Server Message Types

# To Server
# CONNECT <---
# GET
# SAVE
# STATUS
# ANSWER

# From Server
# POLL <---
# CHALLENGE
# RETRIEVE
# STORE

def run_cli(con):

    while True:
        menu_items = ['1', '2', '3']
        print 'Client Menu'
        print '1. Ping Server'
        print '2. Send Arbitrary Data'
        print '3. Save File'
        opt = raw_input('Please Select an Option: ')
        if opt in menu_items:
            {
                '1': lambda: con.ping(),
                '2': lambda: con.send_raw(raw_input('Enter Data to Send:')),
                '3': lambda: con.save_file(raw_input('Enter file path to save:')),
            }[opt]()
        else:
            print 'Not a valid choice.'


def connection_manager(con):

    while True:

        timeout = 0.01
        iready, oready, eready = select.select([con.s], [], [], timeout)

        for sock in iready:

            # Incoming message from Server
            raw_data = sock.recvfrom(1024)[0]

            # Parse out msg type
            msg_type = raw_data[:8]

            # msg type switch case
            fn = {
                POLL: lambda: con.poll(),
            }.get(msg_type)

            if fn is not None:
                fn()
            else:
                print 'Unknown message: %s' % raw_data


if __name__ == '__main__':

    print 'Client Main'

    # Open Connection
    con = ServerConnection()

    # Register With Server as Open Node --> CONNECT
    con.open()

    # Multi-Threading
    cli_thread = threading.Thread(target=run_cli, args=(con,))
    connection_thread = threading.Thread(target=connection_manager, args=(con,))

    # Set as daemons so they die when main thread exits
    cli_thread.daemon = True
    connection_thread.daemon = True

    # Run daemons (threads)
    cli_thread.start()
    connection_thread.start()

    try:
        while True:
            time.sleep(100)

    except KeyboardInterrupt:
        con.close()


