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
        self.readables = [self.__socket]

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
        s_uuid = self.s_uuid+'.UP'
        request = dns_handler.make_fake_request(HOST_NAME, s_uuid, data)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        logging.debug('Send data in DNS request')
        logging.debug(request)

    def __request_down_msg(self):
        '''
        请求用户下行数据 SESSION_UUID.DOWN.hostname.domain
        '''
        request = dns_handler.make_fake_request(HOST_NAME, self.s_uuid, DOWN_MSG)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)

    def __decode_down_msg(self, response):
        '''
        解析用户下行数据
        '''
        txt_records = dns_handler.txt_from_dns_response(response)
        if len(txt_records) < 1:
            logging.debug('No TXT record in response')
            return
        txt_record = txt_records[0]
        bytes_write = bytes.fromhex(txt_record)
        return bytes_write

    def __decode_login_msg(self, response):
        '''
        解析用户登录响应
        '''
        txt_records = dns_handler.txt_from_dns_response(response)
        assert len(txt_records) == 1
        txt_record = txt_records[0]
        self.tun_fd, tun_name = create_tunnel()
        self.readables.append(self.tun_fd)
        self.s_uuid, local_ip, peer_ip = txt_record.split(';')
        logging.info('Session UUID: %s \tLocal ip: %s\tPeer ip: %s', self.s_uuid, local_ip, peer_ip)
        start_tunnel(tun_name, local_ip, peer_ip)
        logging.info('Create Tun Successfully! Tun ID = %d', self.tun_fd)

    def __handle_dns_response(self, response):
        '''
        处理UDP客户端接受的
        '''
        name_data = dns_handler.decode_dns_question(response)
        if name_data[1] == LOGIN_MSG:   # b'LOGIN':
            logging.info('Connect to server successful')
            self.__decode_login_msg(response)
            return
        if name_data[1] == DOWN_MSG:    # b'DOWN':
            bytes_write = self.__decode_down_msg(response)
            logging.debug(bytes_write)
            if bytes_write is not None and len(bytes_write) > 20:
                # Check if IPPacket
                print(IPPacket.str_info(bytes_write))
                os.write(self.tun_fd, bytes_write)
            return
        if name_data[1] == UP_MSG:      # b'UP'
            logging.error('Server Response Invalid Question')
            return

    def run_forever(self):
        '''
        运行代理客户端
        '''
        print('Start connect to server...')
        self.__request_login_msg()
        self.tun_fd = self.__socket
        while True:
            print(self.readables)
            try:
                readable_fd = select(self.readables, [], [], 10)[0]
            except KeyboardInterrupt:
                # TODO: close the connection
                raise KeyboardInterrupt
            for _fd in readable_fd:
                if _fd == self.__socket:
                    pass
                else:
                    # 将从Tun拿到的IP包发送给代理服务器
                    ip_packet = os.read(self.tun_fd, BUFFER_SIZE)
                    logging.debug('Get outbounding data from TUN')
                    self.__request_up_msg(ip_packet)
            # 发送心跳包，尝试接受数据
            logging.debug('Try to receive data')
            self.__request_down_msg()
            # Try to receive data
            try:
                response, _addr = self.__socket.recvfrom(2048)
                logging.info('Receive data from %s', _addr)
            except socket.timeout:
                # self.__request_down_msg()
                continue
            self.__handle_dns_response(response)

if __name__ == '__main__':
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    try:
        Client().run_forever()
    except KeyboardInterrupt:
        print('Closing vpn client ...')
