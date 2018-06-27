#!/usr/bin/env python3
import binascii
import collections
import hashlib
import random
import os
import socketserver
import string
import sys

from flag import FLAG

HOST = ""
PORT = 5419

def bytestobits(b):
    return [(byte >> (7-i)) & 1 for byte in b for i in range(8)]

def bitstobytes(b):
    return bytes([sum(b[i+j] << (7-j) for j in range(8)) for i in range(0, len(b), 8)])

def trivium(key, iv, numbytes):
    assert(len(key) == 10)
    assert(len(iv) == 10)

    init_list = bytestobits(key)
    init_list += [0]*13

    init_list += bytestobits(iv)
    init_list += [0]*4

    init_list += [0]*108
    init_list += [1, 1, 1]
    state = collections.deque(init_list)

    def genbit():
        t_1 = state[65]  ^ state[92]
        t_2 = state[161] ^ state[176]
        t_3 = state[242] ^ state[287]

        out = t_1 ^ t_2 ^ t_3

        s_1 = t_1 ^ state[90]  & state[91]  ^ state[170]
        s_2 = t_2 ^ state[174] & state[175] ^ state[263]
        s_3 = t_3 ^ state[285] & state[286] ^ state[68]

        state.rotate(1)

        state[0] = s_3
        state[93] = s_1
        state[177] = s_2

        return out

    # warmup
    for i in range(576):
        genbit()

    # generate keystream
    stream = [genbit() for i in range(8*numbytes)]

    return bitstobytes(stream)

def test():
    l = [0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1]
    b = b'\x12\x34\x56\x78'
    assert bytestobits(bitstobytes(l)) == l
    assert bitstobytes(bytestobits(b)) == b
    assert bytestobits(b'\xf0') == [1, 1, 1, 1, 0, 0, 0, 0]

test()

class trivialHandler(socketserver.BaseRequestHandler):
    def myrecv(self, n):
        x = self.request.recv(n)
        if n > 0 and x == b'':
            sys.exit(1)
        return x

    def recvline(self, limit):
        s = b""
        while not s.endswith(b"\n") and len(s) <= limit:
            s += self.myrecv(1)
        return s

    def handle(self):
        # proof of work
        prefix = "".join(random.choice(string.digits+string.ascii_letters) for i in range(10))
        self.request.sendall("Give me a string starting with {} of length {} so its sha256sum ends in ffffff.\n".format(prefix, len(prefix)+6).encode('utf8'))
        l = self.recvline(len(prefix)+6+1).strip()
        if len(l) != len(prefix)+6 or not l.startswith(prefix.encode('utf8')) or hashlib.sha256(l).hexdigest()[-6:] != "ffffff":
            self.request.sendall(b"Nope.\n")
            return

        # the good stuff
        self.key = os.urandom(10)

        self.request.sendall(b"Commands:\n    keystream [iv] [number of bytes]\n    guess [key]\n")
        for i in range(5000):
            l = self.recvline(48).strip().split()
            if l[0] == b"keystream":
                iv = binascii.unhexlify(l[1])
                numbytes = int(l[2])
                if 1 <= numbytes <= 16 and len(iv) == 10:
                    stream = trivium(self.key, iv, numbytes)
                    self.request.sendall(binascii.hexlify(stream)+b"\n")
                else:
                    self.request.sendall(b"Invalid format.\n")
            elif l[0] == b"guess":
                if len(l) == 2 and binascii.unhexlify(l[1]) == self.key:
                    self.request.sendall("Congrats! {}\n".format(FLAG).encode('utf8'))
                else:
                    self.request.sendall(b"Nope.\n")
                return
            else:
                self.request.sendall(b"Invalid command!\n")

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((HOST, PORT), trivialHandler)
    server.serve_forever()
