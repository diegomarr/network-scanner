import optparse
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP
from colorama import Fore
from colorama import Style
from prettytable import PrettyTable
import psutil


def getArguments():
    
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="target IP/ IP Range")
    args_options, arguments = parser.parse_args()

    return args_options

def createPacket(ip):
    arp_request = scapy.ARP(pdst=ip) # Create an ARP request object by Scapy
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # Set the destination
    arp_request_broadcast = broadcast / arp_request

    return(arp_request_broadcast)

def transmitPacket(packet):
    success_list, failure_list = scapy.srp(packet, timeout=1)
    return success_list

def parseResponse(success_list):
    targets = []

    for success in success_list:
        entry = {'ip': success[1].psrc, 'mac': success[1].hwsrc}
        targets.append(entry)

    return targets

def get_os(ip_addrs):
    ttl_values = {32: "Windows", 60: "MAC OS", 64: "Linux", 128: "Windows", 255: "Linux 2.4 Kernal"}
    ans = scapy.sr1(IP(dst=str(ip_addrs)) / ICMP(), timeout=1, verbose=0)

    if ans:
        if ans.ttl in ttl_values:
            return ttl_values.get(ans.ttl)
        else:
            return "Could not figure the OS version"
    else:
        return "Packets could not send successfully"

def print_analysis(element_entries):
    table = PrettyTable([f"{Fore.GREEN}IP", "MAC", f"OS{Style.RESET_ALL}"])
    for element in element_entries:
        table.add_row([element["ip"], element["mac"], get_os(element["ip"])])

    print(table)


options = getArguments()

if options.target is not None:
    broadcast_packet = createPacket(options.target)
    success_packets = transmitPacket(broadcast_packet)
    entries = parseResponse(success_packets)
    print_analysis(entries)
