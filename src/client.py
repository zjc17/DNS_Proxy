# -*- coding: utf-8 -*-
'''
测试客户端：
    - 维护TUN
    - 监听数据
    - 修改数据包
'''
import logging
import time
import os
import socket
import struct
import uuid as UUID_GENERATOR
from threading import Thread
from fcntl import ioctl
from select import select
from core import dns_handler
from core.packet import IPPacket

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%H:%M:%S')

UUID = '779ea091-ad7d-43bf-8afc-8b94fdb576bf'
MTU = 180
BUFFER_SIZE = 4096
KEEPALIVE = 10
DOMAIN_NS_IP = '120.78.166.34'
HOST_NAME = 'group11.cs305.fun'
# HOST_NAME = 'www.ibbb.top'
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
LOGIN_MSG = b'LOGIN'    # 用户登录消息 USER_UUID.LOGIN.hostname.domain
DOWN_MSG = b'DOWN'      # 用户下行数据 SESSION_UUID.DOWN.hostname.domain
UP_MSG = b'UP'          # 用户上行数据 SESSION_UUID.UP.$BYTE_DATA.hostname.domain
CLOSED_SESSION_MSG = b'CLOSED_SESSION_MSG'
MAX_KEEP_ASK = 1

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

class SessionExpiredException(Exception):
    '''
    Expection Trigged when the client detects login out
    '''


class Client():
    '''
    代理客户端
    '''

    def __init__(self):
        '''
        初始化代理客户端
        - 心跳包管理
        - 常规查询包，keep_ask
        '''
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__socket.settimeout(5)
        self.__init_local_ip()
        self.s_uuid = None # UUID for session
        self.readables = [self.__socket]
        self.tun_fd = None
        # self.__keep_alive()
        self.keep_ask = MAX_KEEP_ASK


    def __init_local_ip(self):
        '''
        获取本机ip
        '''
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.connect(('8.8.8.8', 80))
        self.local_ip = _socket.getsockname()[0]
        logging.info('Local IP: %s', self.local_ip)
        _socket.close()

    def __keep_alive(self):
        '''
        子线程保持向服务端发送心跳包，以防止服务端清除会话断开隧道连接
        '''
        def _keepalive():
            while True:
                time.sleep(KEEPALIVE)
                self.__request_down_msg()
        c_t_1 = Thread(target=_keepalive, args=(), name='keep_alive')
        c_t_1.setDaemon(True)
        c_t_1.start()

    def __keep_ask(self, keep: bool):
        '''
        keep_ask:
        - 每次发包后置为10
        - 每次收到空包-1
        - 收包后+1
        - 上限为10
        '''
        if keep and self.keep_ask < MAX_KEEP_ASK:
            self.keep_ask += 1
        elif not keep and self.keep_ask > 0:
            self.keep_ask -= 1

    def __handle_login(self):
        '''
        连接服务端并配置代理隧道\n
        创建Tunfd\n
        用户登录消息 USER_UUID.LOGIN.hostname.domain
        '''
        request = dns_handler.make_fake_request(HOST_NAME, UUID, LOGIN_MSG)
        # TODO: handle timeout Exception
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        logging.info('Send data in DNS request')
        response, _addr = self.__socket.recvfrom(2048)
        while True:
            try:
                if self.__decode_login_msg(response):
                    break
                else:
                    self.__socket.sendto(request, DOMAIN_NS_ADDR)
                    logging.info('Send data in DNS request')
            except AssertionError:
                logging.info('Server Down or Not Detected Login Message')
                time.sleep(1)
                continue
        logging.info('Connect to server successful')

    def __request_up_msg(self, data: bytes):
        '''
        请求用户上行数据 SESSION_UUID.<UNIQUE_ID>.UP.$BYTE_DATA.hostname.domain
        '''
        s_uuid = self.s_uuid+'.UP.'+ str(UUID_GENERATOR.uuid1())[:8]
        request = dns_handler.make_fake_request(HOST_NAME, s_uuid, data)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        logging.info('Send data in DNS request')
        logging.debug(request)
        # 发包后置为10
        # self.keep_ask = MAX_KEEP_ASK
        # self.__request_down_msg()
        self.__keep_ask(True)

    def __request_down_msg(self):
        '''
        请求用户下行数据 SESSION_UUID.DOWN.<RANDOM_UUID>.hostname.domain
        '''
        time.sleep(0.01)
        d_uuid = self.s_uuid+'.DOWN'
        r_uuid = str(UUID_GENERATOR.uuid1())
        request = dns_handler.make_fake_request(HOST_NAME, d_uuid,
                                                r_uuid.encode())
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        logging.info('Send DOWN MSG in DNS request %s', r_uuid)

    @staticmethod
    def __decode_down_msg(response):
        '''
        解析用户下行数据
        '''
        txt_records = dns_handler.txt_from_dns_response(response)
        if len(txt_records) < 1:
            logging.debug('No TXT record in response')
            return b''
        txt_record = txt_records[0]
        bytes_write = bytes.fromhex(txt_record)
        return bytes_write

    def __decode_login_msg(self, response):
        '''
        解析用户登录响应
        '''
        name_data = dns_handler.decode_dns_question(response)
        if name_data[1] != LOGIN_MSG:
            logging.debug('Not a Login response <%s>', name_data[1])
            return False
        txt_records = dns_handler.txt_from_dns_response(response)
        assert len(txt_records) == 1
        txt_record = txt_records[0]
        self.tun_fd, tun_name = create_tunnel()
        self.readables.append(self.tun_fd)
        self.s_uuid, local_ip, peer_ip = txt_record.split(';')
        logging.info('Session UUID: %s \tLocal ip: %s\tPeer ip: %s', self.s_uuid, local_ip, peer_ip)
        start_tunnel(tun_name, local_ip, peer_ip)
        logging.info('Create Tun Successfully! Tun ID = %d', self.tun_fd)
        return True

    def __handle_dns_response(self, response):
        '''
        处理UDP客户端接受的
        '''
        name_data = dns_handler.decode_dns_question(response)
        if name_data[1] == LOGIN_MSG:   # b'LOGIN':
            logging.error('Ignore Server Response: Already Login')
            return
        if name_data[1] == DOWN_MSG:    # b'DOWN':
            logging.debug('Receive Packet from server %s', name_data[2])

            bytes_write = self.__decode_down_msg(response)
            if bytes_write == CLOSED_SESSION_MSG:
                # 重新登录
                # - 关闭旧的session, 原地发起登录请求
                logging.info('客户端掉线，重新登录')
                # - 删除旧的文件描述符
                os.close(self.readables[1])
                self.readables = [self.__socket]
                self.__handle_login()
            elif bytes_write is not None and len(bytes_write) > 20:
                # Check if IPPacket
                # logging.info(IPPacket.str_info(bytes_write))
                logging.debug('Write data into TUN')
                logging.info(bytes_write)
                os.write(self.tun_fd, bytes_write)
                # 收到数据包后+1
                logging.debug('+')
                self.__keep_ask(True)
            else:
                # 收到空包后-1
                logging.debug('-')
                self.__keep_ask(False)
            return
        if name_data[1] == UP_MSG:      # b'UP'
            logging.debug('Server Response Invalid Question')
            return

    def __handle_forwarding(self):
        '''
        客户端登录后的转发行为
        '''
        while True:
            readable_fd = select(self.readables, [], [], 10)[0]
            for _fd in readable_fd:
                if _fd == self.__socket:
                    response, _addr = self.__socket.recvfrom(2048)
                    self.__handle_dns_response(response)
                else:
                    # 将从Tun拿到的IP包发送给代理服务器
                    ip_packet = os.read(self.tun_fd, BUFFER_SIZE)
                    logging.debug('Get outbounding data from TUN')
                    self.__request_up_msg(ip_packet)
            # 发送心跳包，尝试接受数据
            logging.debug('keep_ask = [%d]', self.keep_ask)
            if self.keep_ask > 0:
                logging.info('Try To Receive Data [%d]', self.keep_ask)
                self.__request_down_msg()

    def run_forever(self):
        '''
        运行代理客户端
        '''
        logging.info('Start connect to server...')
        self.__handle_login()
        while True:
            try:
                self.__handle_forwarding()
            except SessionExpiredException:
                logging.error('SessionExpiredException')
                self.__handle_login()
                continue
            except KeyboardInterrupt:
                # TODO: close the connection
                raise KeyboardInterrupt

if __name__ == '__main__':
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    DOMAIN_NS_ADDR = ('8.8.8.8', 53)
    DOMAIN_NS_ADDR = ('18.162.114.192', 53)
    # DOMAIN_NS_ADDR = ('18.162.51.192', 53) # 29 Kbps

    try:
        Client().run_forever()
    except KeyboardInterrupt:
        logging.info('Closing vpn client ...')
