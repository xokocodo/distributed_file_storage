import logging
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

# Define Message Types
CONNECT = 'CONNECT\x00'
CONNECT_FAIL_AUTH = 'C_BADAUTH'
CONNECT_SUCESS = 'C_GOOD\x00\x00'
FILE_START = 'F_START\x00'
FILE_END = 'F_END\x00\x00\x00'
FILE_DATA = 'F_DATA\x00\x00'
FILE_GOOD = 'F_GOOD\x00\x00'
FILE_BAD_HASH = 'F_BADHAS'
FILE_BAD_UID = 'F_BADUID\x00'
FILE_BAD_SEQ = 'F_BADSEQ\x00'
FILE_DELETE = 'F_DEL\x00\x00\x00'
FILE_DELETE_GOOD = 'F_DEL_G\x00'
FILE_DELETE_BAD_AUTH = 'F_DEL_BA'
FILE_DELETE_BAD_OWNER = 'F_DEL_BO'
FILE_DELETE_BAD_UID = 'F_DEL_BI'
FILE_GET_REQUEST = 'F_GET\x00\x00\x00'
FILE_GET_BAD_UID = 'F_GET_BI'
STATUS_GOOD = 'S_GOOD\x00\x00'
STATUS_BAD = 'S_BAD\x00\x00\x00'
FORMAT_FAILURE = 'BAD_FORM'
PING = 'PING\x00\x00\x00\x00'
PONG = 'PONG\x00\x00\x00\x00'
POLL = 'POLL\x00\x00\x00\x00'
UNKOWN_MSG_RECV = '\xff' * 8

PROTOCOL_HEADER = '\xa5\x8b\xb8\x5a'

# Addresses and Ports
SERVER_ADDRESS = '68.6.174.164'
HOST =  '192.168.1.97'
PORT = 7031

# Define Folder Locations
SERVER_FILE_DESTINATION_FOLDER = '/home/daniel/Desktop/storage/'
CLIENT_FILE_DESTINATION_FOLDER = '/Users/xokocodo/Playground/storage/'
CLIENT_KEY_FOLDER = '/Users/xokocodo/Playground/storage/keys/'

# Set Up Logging
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Define Log Function
def log(string):
    logger.debug(string)


class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key).digest()

    @staticmethod
    def get_key():
        return Random.new().read(256)

    @staticmethod
    def get_iv():
        return Random.new().read(AES.block_size)

    def encrypt(self, data, iv):
        raw = self._pad(data)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.encrypt(raw)

    def decrypt(self, data, iv):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(data))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]