#! usr/bin/env python

import scapy.all as scapy
import optparse
import subprocess

def process():
    subprocess.call(["clear"])

def options():
    info = optparse.OptionParser()
    info.add_option("-i", "--ip", dest="ip_adderess", help="Please insert ip address or subnet after -i or --ip")
    value, argument = info.parse_args()
    if not value.ip_adderess:
        info.error("Please Enter IP Address or Subnet For more information type --help after script")
    else:
        return value


def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_packet = broadcast / arp_packet
    positive_responce, negative_responce = scapy.srp(broadcast_arp_packet, timeout=15)#, verbose=False)
    print("\n\t\t\t\tThe Following IP Address and Mac Address Connected connected to network are\n\n\t\t\t\t\t\t-----------------------------------------\n\t\t\t\t\t\tIP\t\t\tMac Address\n\t\t\t\t\t\t-----------------------------------------")
    for lines in positive_responce:
        print("\t\t\t\t\t\t" + lines[1].psrc + "\t\t" + lines[1].hwsrc)
    print("\t\t\t\t\t\t-----------------------------------------")

process()
value = options()
scan(value.ip_adderess)
