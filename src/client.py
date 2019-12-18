# -*- coding: utf-8 -*-
'''
测试客户端：
    - 维护TUN
    - 监听数据
    - 修改数据包
'''
import logging
import os
import re
import socket
import struct
import sys
from fcntl import ioctl
from select import select

from dnslib import DNSRecord
from dnslib.dns import DNSError

from core import dns_handler
from core.packet import IPPacket

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')

UUID = '779ea091-ad7d-43bf-8afc-8b94fdb576bf'

MTU = 1400
BUFFER_SIZE = 4096
KEEPALIVE = 10
DOMAIN_NS_IP = '120.78.166.34'
HOST_NAME = 'group11.cs305.fun'
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
LOGIN_MSG = b'LOGIN'    # 用户登录消息 USER_UUID.LOGIN.hostname.domain
DOWN_MSG = b'DOWN'      # 用户下行数据 SESSION_UUID.DOWN.hostname.domain
UP_MSG = b'UP'          # 用户上行数据 SESSION_UUID.UP.$BYTE_DATA.hostname.domain

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
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.settimeout(5)
        # self.__dst_addr = SERVER_ADDRESS
        self.init_local_ip()
        self.s_uuid = None # UUID for session

    def init_local_ip(self):
        '''
        获取本机ip
        '''
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.connect(('8.8.8.8', 80))
        self.local_ip = _socket.getsockname()[0]
        print('Local IP:', self.local_ip)
        _socket.close()

    def __request_login_msg(self):
        '''
        连接服务端并配置代理隧道\n
        创建Tunfd\n
        用户登录消息 USER_UUID.LOGIN.hostname.domain
        '''
        request = dns_handler.make_fake_request(HOST_NAME, UUID, LOGIN_MSG)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)        
    
    def __request_up_msg(self, data:bytes):
        '''
        请求用户上行数据 SESSION_UUID.UP.$BYTE_DATA.hostname.domain
        '''
        SESSION_UUID = self.s_uuid+'.UP'
        request = dns_handler.make_fake_request(HOST_NAME, SESSION_UUID, data)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
    
    def __request_down_msg(self):
        '''
        请求用户下行数据 SESSION_UUID.DOWN.hostname.domain
        '''
        request = dns_handler.make_fake_request(HOST_NAME, UUID, DOWN_MSG)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
    
    def __decode_down_msg(self, response):
        '''
        解析用户下行数据
        '''
        txt_record = dns_handler.txt_from_dns_response(response)
        logging.debug(bytes.fromhex(txt_record))
            bytes_write = bytes.fromhex(txt_record)
            if bytes_write != b'':
                print(IPPacket.str_info(bytes_write))
                os.write(tunfd, bytes.fromhex(txt_record))
    def __decode_down_msg(self, response):
        '''
        解析用户登录响应
        '''
        txt_record = dns_handler.txt_from_dns_response(response)
        self.tunfd, tun_name = create_tunnel()
        self.s_uuid, local_ip, peer_ip = txt_record.split(';')
        logging.info('Session UUID: %s \tLocal ip: %s\tPeer ip: %s', self.s_uuid, local_ip, peer_ip)
        start_tunnel(tun_name, local_ip, peer_ip)
        logging.info('Create Tun Successfully! Tun ID = %d', tunfd)

    def run_forever(self):
        '''
        运行代理客户端
        '''
        print('Start connect to server...')
        self.__request_login_msg()
        if not tunfd:
            print("Connect failed!")
            sys.exit(0)
        print('Connect to server successful')
        readables = [self.__socket, self.tunfd]
        while True:
            try:
                readable_fd = select(readables, [], [], 10)[0]
            except KeyboardInterrupt:
                # TODO: close the connection
                # self.__app.sendto(b'e', self.__dst_addr)
                raise KeyboardInterrupt
            for fd in readable_fd:
                if fd == self.__socket:
                    # Try to receive data
                    response, _addr = self.__socket.recvfrom(2048)
                    name_data = dns_handler.decode_dns_question(response)
                    if name_data[1] == LOGIN_MSG:   # b'LOGIN':
                        self.__decode_login_msg(response)
                        continue
                    if name_data[1] == DOWN_MSG:    # b'DOWN':
                        self.__decode_down_msg(response)
                        continue
                    if name_data[1] == UP_MSG:      # b'UP'
                        logging.error('Server Response Invalid Question')
                        continue
                else:
                    # 将从Tun拿到的IP包发送给代理服务器
                    ip_packet = os.read(tunfd, BUFFER_SIZE)
                    logging.debug('Get outbounding data from TUN')
                    self.__request_up_msg(ip_packet)
            # 发送心跳包，尝试接受数据
            logging.debug('Try to receive data')
            self.__request_down_msg()

if __name__ == '__main__':
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    try:
        Client().run_forever()
    except KeyboardInterrupt:
        print('Closing vpn client ...')
