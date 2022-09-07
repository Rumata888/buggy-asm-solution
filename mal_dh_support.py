#!/usr/bin/python3
from ctypes import *
import struct
import os
from extra_flag_solver import find_buggy_values
from Crypto.Util.number import long_to_bytes, bytes_to_long

PROTOCOL_MAGIC = b"CTFZone"

DHLIBRARY_NAME = os.path.join(os.path.dirname(__file__), "mallibdh.so")

PRIVATE_KEY_NAME = os.path.join(os.path.dirname(__file__), "pk.bin")


class TooMuchData(Exception):
    pass


class NotEnoughData(Exception):
    pass


def recvMessage(socket):
    size_bytes = b""
    while len(size_bytes) != 4:
        r = socket.recv(4 - len(size_bytes))
        if r == b"":
            raise NotEnoughData
        size_bytes += r
    size = struct.unpack("<I", size_bytes)[0]
    if size > 0x400000:
        raise TooMuchData
    data = b""
    size_left = size
    while size_left > 0:
        if size_left < 1024:
            new_chunk = socket.recv(size_left)
        else:
            new_chunk = socket.recv(1024)
        if new_chunk == b"":
            raise NotEnoughData
        data += new_chunk
        size_left -= len(new_chunk)
    return data


def sendMessage(socket, data):
    if isinstance(data, str):
        data = data.encode()
    size = len(data)
    socket.sendall(struct.pack("<I", size) + data)


class DHLibNotFound(Exception):
    pass


class DHNotALib(Exception):
    pass


class PrivateKeyNotFound(Exception):
    pass


class PrivateKeyWrongSize(Exception):
    pass


class Cryptor:
    def __init__(self, private_key=bytes([])) -> None:
        if not os.path.isfile(DHLIBRARY_NAME):
            raise DHLibNotFound
        try:
            self.dhlib = cdll.LoadLibrary(DHLIBRARY_NAME)
        except OSError:
            raise DHNotALib
        if len(private_key) == 0:
            if not os.path.isfile(PRIVATE_KEY_NAME):
                raise PrivateKeyNotFound
            with open(PRIVATE_KEY_NAME, "rb") as f:
                private_key = f.read(32)
        if len(private_key) != 32:
            raise PrivateKeyWrongSize
        private_key_raw = create_string_buffer(private_key, len(private_key))

        self.dhlib.initializeState.restype = c_void_p
        result = self.dhlib.initializeState(private_key_raw)
        self.protocol_state = cast(result, POINTER(c_uint8))

    def getPublicKey(self) -> bytes:
        public_key_buffer = create_string_buffer(bytes([0] * 64), 64)
        self.dhlib.getPublicKey.restype = c_bool
        self.dhlib.getPublicKey(self.protocol_state, public_key_buffer)
        return bytes(public_key_buffer)

    def double_point(self, point_x, point_y):
        point_buffer = create_string_buffer(
            long_to_bytes(int(point_x), 32)[::-1]
            + long_to_bytes(int(point_y), 32)[::-1],
            64,
        )
        self.dhlib.computeFaulty.restype = c_bool
        self.dhlib.computeFaulty(point_buffer)
        new_point_bytes = bytes(point_buffer)
        return (
            bytes_to_long(new_point_bytes[:32][::-1]),
            bytes_to_long(new_point_bytes[32:][::-1]),
        )

    def createSession(self, other_key):
        if len(other_key) != 64:
            return (False, bytes("Wrong key length"))
        other_key_buffer = create_string_buffer(other_key, 64)
        error_message = create_string_buffer(bytes([0] * 1024), 1024)
        self.dhlib.createSession.restype = c_bool
        result = self.dhlib.createSession(
            self.protocol_state, other_key_buffer, error_message
        )
        return (result, bytes(error_message))

    def encrypt(self, plaintext):
        plaintext = plaintext + bytes([0] * (16 - (len(plaintext) % 16)))
        self.dhlib.encryptWithSessionKey.restype = c_bool
        plaintext_buffer = create_string_buffer(plaintext, len(plaintext))
        ciphertext_buffer = create_string_buffer(
            bytes([0] * len(plaintext)), len(plaintext)
        )
        IV = create_string_buffer(os.urandom(16), 16)
        MAC = create_string_buffer(bytes([0] * 32), 32)
        result = self.dhlib.encryptWithSessionKey(
            self.protocol_state,
            IV,
            plaintext_buffer,
            ciphertext_buffer,
            len(plaintext),
            MAC,
        )
        return (result, bytes(IV), bytes(ciphertext_buffer), bytes(MAC))

    def decrypt(self, iv, ciphertext, mac):
        if (len(ciphertext) % 16) != 0 or len(ciphertext) == 0:
            return (False, "Incorrect format")
        self.dhlib.decryptWithSessionKey.restype = c_bool
        ciphertext_buffer = create_string_buffer(ciphertext, len(ciphertext))
        plaintext_buffer = create_string_buffer(
            bytes([0] * len(ciphertext)), len(ciphertext)
        )
        iv_buffer = create_string_buffer(iv, 16)
        mac_buffer = create_string_buffer(mac, 32)
        result = self.dhlib.decryptWithSessionKey(
            self.protocol_state,
            iv_buffer,
            ciphertext_buffer,
            plaintext_buffer,
            len(ciphertext),
            mac_buffer,
        )
        return (result, bytes(plaintext_buffer))

    def __del__(self):
        self.dhlib.deleteState(self.protocol_state)


PROTOCOL_OK = b"SUCCESS"


class Server:
    class NoTunnel(Exception):
        pass

    def __init__(self, clientSocket, private_key=bytes([])) -> None:
        self.cryptor = Cryptor(private_key)
        self.clientSocket = clientSocket
        self.tunnelEstablished = False

    def establishTunnel(self):
        sendMessage(self.clientSocket, self.cryptor.getPublicKey())
        client_key = recvMessage(self.clientSocket)
        (status, message) = self.createSession(client_key)
        if status:
            sendMessage(self.clientSocket, PROTOCOL_OK)
            self.tunnelEstablished = True
        else:
            sendMessage(self.clientSocket, message.strip(b"\x00"))
        return (self.tunnelEstablished, client_key)

    def receive(self):
        if not self.tunnelEstablished:
            raise Server.NoTunnel
        ciphertext = recvMessage(self.clientSocket)
        if len(ciphertext) < 64:
            return (False, b"")
        mac = ciphertext[:32]
        iv = ciphertext[32:48]
        ciphertext = ciphertext[48:]
        return self.cryptor.decrypt(iv, ciphertext, mac)

    def send(self, message):
        if not self.tunnelEstablished:
            raise Server.NoTunnel
        (result, iv, ct, mac) = self.cryptor.encrypt(message)
        if not result:
            return False

        sendMessage(self.clientSocket, mac + iv + ct)
        return True

    def getPublicKey(self):
        return self.cryptor.getPublicKey()

    def createSession(self, other_key):
        return self.cryptor.createSession(other_key)

    def __del__(self):
        del self.cryptor


class MalClient:
    class NoTunnel(Exception):
        pass

    def __init__(self, serverSocket, private_key=os.urandom(32)) -> None:

        self.cryptor = Cryptor(private_key)
        self.serverSocket = serverSocket
        self.tunnelEstablished = False

    def confirmServer(self):
        sendMessage(self.serverSocket, PROTOCOL_MAGIC)
        if recvMessage(self.serverSocket) != PROTOCOL_MAGIC:
            print("Bad server")
            return False
        return True

    def testPoint(self, point_x, point_y):
        sendMessage(
            self.serverSocket,
            long_to_bytes(int(point_x), 32)[::-1]
            + long_to_bytes(int(point_y), 32)[::-1],
        )
        recvMessage(self.serverSocket)  # key
        return recvMessage(self.serverSocket)

    def establishTunnel(self):
        sendMessage(self.serverSocket, PROTOCOL_MAGIC)
        if recvMessage(self.serverSocket) != PROTOCOL_MAGIC:
            print("Bad server")
            return False
        sendMessage(self.serverSocket, self.cryptor.getPublicKey())
        client_key = recvMessage(self.serverSocket)
        (status, message) = self.createSession(client_key)
        message = message.strip(b"\x00")
        if status:
            if recvMessage(self.serverSocket) == PROTOCOL_OK:
                self.tunnelEstablished = True
            else:
                message = b"Server failed to establish tunnel"

        return (self.tunnelEstablished, message)

    def establishFakeTunnel(self, other_public_key):
        (status, message) = self.createSession(other_public_key)
        message = message.strip(b"\x00")
        if not status:
            message = b"Failed to establish tunnel"
        return (status, message)

    def receiveFake(self, ciphertext):
        if len(ciphertext) < 64:
            return b""
        mac = ciphertext[:32]
        iv = ciphertext[32:48]
        ciphertext = ciphertext[48:]
        return self.cryptor.decrypt(iv, ciphertext, mac)

    def receive(self):
        if not self.tunnelEstablished:
            raise Server.NoTunnel
        ciphertext = recvMessage(self.serverSocket)
        if len(ciphertext) < 64:
            return b""
        mac = ciphertext[:32]
        iv = ciphertext[32:48]
        ciphertext = ciphertext[48:]
        return self.cryptor.decrypt(iv, ciphertext, mac)

    def send(self, message):
        if not self.tunnelEstablished:
            raise Server.NoTunnel
        (result, iv, ct, mac) = self.cryptor.encrypt(message)
        if not result:
            return False

        sendMessage(self.serverSocket, mac + iv + ct)
        return True

    def getPublicKey(self):
        return self.cryptor.getPublicKey()

    def createSession(self, other_key):
        return self.cryptor.createSession(other_key)

    def __del__(self):
        del self.cryptor
