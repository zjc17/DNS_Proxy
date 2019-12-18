# -*- coding: utf-8 -*-
'''
测试客户端：
    - 维护TUN
    - 监听数据
    - 修改数据包
'''
import os
import re
import sys
import time
import struct
import socket
from core import dns_handler
from fcntl import ioctl
from select import select
from threading import Thread
from core.packet import IPPacket, UDPPacket
from dnslib import DNSRecord
from dnslib.dns import DNSError
import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')

UUID = '779ea091-ad7d-43bf-8afc-8b94fdb576bf'

MTU = 1400
BUFFER_SIZE = 4096
KEEPALIVE = 10

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002


def create_tunnel(tun_name='tun%d', tun_mode=IFF_TUN):
    '''
    创建隧道
    '''
    tunfd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tunfd, TUNSETIFF, struct.pack(
        b"16sH", tun_name.encode(), tun_mode))
    tun_name = ifn[:16].decode().strip("\x00")
    return tunfd, tun_name


def start_tunnel(tun_name, local_ip, peer_ip):
    '''
    配置隧道并启动
    '''
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tun_name, local_ip, peer_ip, MTU)).read()


class Client():
    '''
    代理客户端
    '''

    def __init__(self):
        self.__app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__app.settimeout(5)
        # self.__dst_addr = SERVER_ADDRESS
        self.init_local_ip()

    def init_local_ip(self):
        '''
        获取本机ip
        '''
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.connect(('8.8.8.8', 80))
        self.local_ip = _socket.getsockname()[0]
        print('Local IP:', self.local_ip)
        _socket.close()

    def keep_alive(self):
        '''
        子线程保持向服务端发送心跳包，以防止服务端清除会话断开隧道连接
        TODO: 修改心跳包发送方式
            - DNS查询
        '''
        def _keepalive(udp, dst_addr):
            while True:
                time.sleep(KEEPALIVE)
                udp.sendto(b'\x00', dst_addr)
        # k = Thread(target=_keepalive, args=(
            # self.__app, self.__dst_addr), name='keep_alive')
        # k.setDaemon(True)
        # k.start()

    def login(self):
        '''
        连接服务端并配置代理隧道
        '''
        request = dns_handler.make_fake_request(HOST_NAME, UUID, b'LOGIN')
        # self.__app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__app.sendto(request, DOMAIN_NS_ADDR)
        response, _addr = self.__app.recvfrom(2048)
        response = str(DNSRecord().parse(response))
        # print(response)
        txt_records = re.findall(r'.*TXT.*\"(.*)\".*', response)
        assert len(txt_records) == 1
        txt_record = txt_records[0]
        tunfd, tun_name = create_tunnel()
        local_ip, peer_ip = txt_record.split(';')
        logging.info('Local ip: %s\tPeer ip: %s' % (local_ip, peer_ip))
        start_tunnel(tun_name, local_ip, peer_ip)
        logging.info('Create Tun Successfully! Tun ID = %d'% tunfd)
        return tunfd

    def get_data_from_response(self, data):
        _idx = 12
        _LEN = data[_idx]
        _name = []
        while _LEN != 0:
            _idx += 1 
            _name.append(data[_idx:_idx+_LEN])
            _idx += _LEN
            _LEN = data[_idx]
        DATA = b''.join(_name[1:-3])
        UUID = _name[0].decode()
        print(IPPacket.str_info(DATA))
        return DATA

    def run_forever(self):
        '''
        运行代理客户端
        '''
        print('Start connect to server...')
        tunfd = self.login()
        if not tunfd:
            print("Connect failed!")
            sys.exit(0)
        print('Connect to server successful')
        # self.keep_alive()
        readables = [self.__app, tunfd]
        while True:
            try:
                readab = select(readables, [], [], 10)[0]
            except KeyboardInterrupt:
                # TODO: close the connection
                # self.__app.sendto(b'e', self.__dst_addr)
                raise KeyboardInterrupt
            for _r in readab:
                if _r == self.__app:
                    # receiving data
                    data, addr = self.__app.recvfrom(BUFFER_SIZE)
                    logging.debug('Receive data from TUN')
                    print(data)
                    DATA = self.get_data_from_response(data)
                    try:
                        os.write(tunfd, DATA)
                    except OSError:
                        if data == b'r':
                            os.close(tunfd)
                            readables.remove(tunfd)
                            print('Reconnecting...')
                            tunfd = self.login()
                            readables.append(tunfd)
                        continue
                else:
                    # sending data
                    data = os.read(tunfd, BUFFER_SIZE)
                    # TODO: 将应用数据发送给代理服务器
                    logging.debug('Get outbounding data from TUN')
                    # data = data[:12] + b'\n\x00\x00\x02\n\x00\x00\x01' + data[20:]
                    # logging.debug('Rewrite data: %s'%IPPacket.str_info(data))
                    request = dns_handler.make_fake_request(HOST_NAME, UUID, data)
                    self.__app.sendto(request, DOMAIN_NS_ADDR)
            logging.debug('Try to receive data')
            # Try to receive data
            request = dns_handler.make_fake_request(HOST_NAME, UUID, b'KEEP_ALIVE')
            # self.__app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.__app.sendto(request, DOMAIN_NS_ADDR)
                response, _addr = self.__app.recvfrom(2048)
                response = str(DNSRecord().parse(response))
                print(response)
                txt_records = re.findall(r'.*TXT.*\"(.*)\".*', response)
                assert len(txt_records) == 1
                txt_record = txt_records[0]
                logging.debug(bytes.fromhex(txt_record))
                bytes_write = bytes.fromhex(txt_record)
                
                if bytes_write != b'':
                    print(IPPacket.str_info(bytes_write))
                    os.write(tunfd, bytes.fromhex(txt_record))
            except DNSError:
                logging.debug('DNSError')

DOMAIN_NS_IP = '120.78.166.34'
HOST_NAME = 'group11.cs305.fun'

def get_txt_record(name:str)->str:
    if name:
        name += '.'
    reply = os.popen('dig -t txt @{} {}'.format(DOMAIN_NS_IP, name+HOST_NAME)).read()
    import re
    txt_records = re.findall(r'.*TXT.*\"(.*)\".*', reply)
    print(reply)
    assert len(txt_records) == 1
    return txt_records[0]
    

if __name__ == '__main__':
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    try:
        Client().run_forever()
    except KeyboardInterrupt:
        print('Closing vpn client ...')
