#!user/bin/env

r""" This script is used to scan a particular IP or a range of IP and print out the IPs and MAC of all the devices connected to same network in a table formatt.
     It imports two packages >>>
     - argparse : Its an udated version of "optparse" from python2. It gets the command line arguments and parse their values.
     - scapy : This package scans the given network for all connected IPs on the same network and their MAC.
"""

import scapy.all as scapy
import argparse


def get_cmd_args():
    r""" This function gets the command line args and returns the taget IP or IP range as a string.
         It gets >>>
          -t or --target for target IP or IP range.
          -h or --help if you want any further details.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Targt IP / IP Range")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP or an IP range.For more details use -h or --help.")
    return options.target

def scan(ip):
    r"""This function gets the target IP or IP range and returns a list of answered IPs and their MAC adresses.
        The returned list is a list of dictionaries having two keys - "ip" and "mac".
        :param ip:Target IP or IP range
        :return: List of answered IPs and their MAC adresses
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast , timeout = 1, verbose=False)[0]
    target_list=[]
    for element in answered_list:
        target_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        target_list.append(target_dict)
    return target_list

def print_scan_result(target_list):
    r""" This function prints all the IPs and their corresponding MAC in a table formatt.
        :param target_list: List of dictionary of IPs and MACs
        :return: NONE
    """
    print("   IP\t\t\t   MAC Address\n-----------------------------------------")
    for element in target_list:
        print(element["ip"] + "\t\t" + element["mac"])


target_ip = get_cmd_args()
target_list = scan(target_ip)
print_scan_result(target_list)