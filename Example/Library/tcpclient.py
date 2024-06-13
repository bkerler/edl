import socket
from binascii import hexlify


class tcpclient:
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ("localhost", port)
        print("connecting to %s port %s" % server_address)
        self.sock.connect(server_address)

    def sendcommands(self, commands):
        try:
            for command in commands:
                self.sock.sendall(bytes(command, 'utf-8'))
                data = ""
                while "<ACK>" not in data and "<NAK>" not in data:
                    tmp = self.sock.recv(4096)
                    if tmp == b"":
                        continue
                    try:
                        data += tmp.decode('utf-8')
                    except:
                        data += hexlify(tmp)
                print(data)
        finally:
            print("closing socket")
            self.sock.close()
