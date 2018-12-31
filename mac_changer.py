#!user/bin/env

r""" >>>   python mac_changer.py -i 'interface' -m 'new mac adress'   <<<
     This script changes the current MAC address of the given interface to the new MAC address passed.
     It accepts two command line arguments >>>
     * -i or --interface : Interface whose MAC address to be changed.
     * -m or --mac       : MAC address to be assigned to the interface.

     The scripts imports following packages >>>
     * subprocess : It runs the commands passed on the command shell.
     * optparse  : It gets the command line arguments and parse their values. (an updated version of this package - "argparse" is included in python3).
     * re        : It finds the pattern in the given string.
"""

import subprocess
import optparse
import re

def get_cmd_args():
    r""" This function gets the command line arguments and returns them as key and values.
         The two keys are >>>
         - [variable_name].interface : It contains the name of the interface passed to the script.
         - [varible_name].new_mac : It contains the MAC address passed to the script.
    :return: A variable containing two keys - interface and new_mac.
    """
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Interface to change its MAC address")
    parser.add_option("-m","--mac",dest="new_mac",help="New MAC address of the interface")
    (options,args) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface.For more details use -h or --help.")
    elif not options.new_mac:
        parser.error("[-] Please specify a MAC address.For more details use -h or --help.")
    return options

def get_current_mac(interface):
    r""" This function gets the interface name and gets its returns its current MAC adress.
    :param interface: Name of interface whose MAC adress to be returned.
    :return: MAC address of the interface stored as a string in a variable.
    """
    ifconfig_result = str(subprocess.check_output(["ifconfig", interface]))
    mac_search_result=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result)
    if mac_search_result:
        return mac_search_result.group(0)
    else:
        print("[-] MAC address not found.")
        exit()

def change_mac(interface,new_mac):
    r""" This function changes the MAC address of the interface to the new MAC address passed.It accepts two arguments - name of the interface and the MAC address to be assigned.
    :param interface: Name of the interface to change its MAC address.
    :param new_mac: MAC adress to be assigned.
    :return: NONE
    """
    print("[+] Changing MAC adress of "+interface+" to "+new_mac)
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig", interface,"up"])


options = get_cmd_args()

current_mac = get_current_mac(options.interface)
print("[+] Current MAC address of "+options.interface+" is "+current_mac)

change_mac(options.interface,options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC adress changed successfully !!!")
else:
    print("[-] Unable to change MAC address !!!")
