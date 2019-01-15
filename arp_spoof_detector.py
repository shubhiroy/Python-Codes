#!user/bin/env

r""" >>>   python arp_spoof_detector.py -i 'interface' <<<
     This script checks the 'is-at' ARP packets sent to the host machine and detects if the sender is actually at the said IP address or not.
     The script imports following modules -
     - argparse :  To parse arguments passed with the script in the command shell.
     - scapy.all : To sniff the data packet flowing through the interface.
"""

import scapy.all as scapy
import argparse

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
    return options


def get_mac(ip):
    r""" This function returns the MAC address of the IP passed.
    :param ip: IP address whose MAC address to be found.
    :return: MAC address of the IP passed.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast , timeout = 1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniff(interface):
    r""" This function sniffs the data packets flowing through the interface.This function call backs another function - process_sniffed_packet.
        :param interface: Interface through which flowing data packets have to be sniffed.
        :return:NONE
        """
    scapy.sniff(iface=interface,store=False,prn=process_packet)


def process_packet(packet):
    r""" This function process the given data packet. It filters the packets with ARP layer with op type 'is-at' and reinsures if the IP - MAC adress info  told by the sender machine is correct by getting its MAC adress using the sent IP adress and matching it with the sender's MAC address.
    It calls back another method -
    * get_mac(packets) : It get the MAC address of the machine linked with the IP address passed as parameter
        :param packet: Data packet to be processed.
        :return: NONE
        """
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 :
        real_mac = get_mac(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc
        try :
            if real_mac != response_mac :
                print("[+] You are under attack from MAC = "+response_mac+" !!!")
        except IndexError:
            pass


interface = get_cmd_args().interface
while(True):
    try:
        sniff(interface)
    except IndexError:
        pass

