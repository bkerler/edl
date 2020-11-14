import socket

class tcpclient():
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ("localhost", port)
        print("connecting to %s port %s" % server_address)
        self.sock.connect(server_address)

    def sendcommands(self,commands):
        try:
            for command in commands:
                self.sock.sendall(bytes(command, 'utf-8'))
                amount_received = 0
                amount_expected = 3
                while amount_received < amount_expected:
                    data = self.sock.recv(4096)
                    if data == b"":
                        break
                    amount_received += len(data)
                    # print("received %s" % data)
                data = data.decode('utf-8').split("\n")
                if data[0] == "<ACK>":
                    print(data[1])
                else:
                    if len(data)>1:
                        print("Error: " + data[1])
                    else:
                        print("Unknown error !")
        finally:
            print("closing socket")
            self.sock.close()


