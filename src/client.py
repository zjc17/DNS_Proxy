# -*- coding: utf-8 -*-
'''
测试客户端：
    - 维护TUN
    - 监听数据
    - 修改数据包
'''
import time
import os
import socket
import uuid as UUID_GENERATOR
from threading import Thread
from select import select
from core.dns_handler import Decapsulator, Encapsulator
from core.sys_manage import TunManager
from core.logger import logging, create_logger
COLOR_LOG = create_logger(__name__, logging.DEBUG)

UUID = '779ea091-ad7d-43bf-8afc-8b94fdb576bf'
MTU = 180
BUFFER_SIZE = 4096
KEEPALIVE = 10
DOMAIN_NS_IP = '120.78.166.34'
HOST_NAME = 'group11.cs305.fun'
HOST_NAME = 'www.ibbb.top'
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
LOGIN_MSG = b'LOGIN'    # 用户登录消息 USER_UUID.LOGIN.hostname.domain
DOWN_MSG = b'DOWN'      # 用户下行数据 SESSION_UUID.DOWN.hostname.domain
UP_MSG = b'UP'          # 用户上行数据 SESSION_UUID.UP.$BYTE_DATA.hostname.domain
CLOSED_SESSION_MSG = b'CLOSED_SESSION_MSG'
MAX_KEEP_ASK = 1



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
        self.init_local_ip()
        self.s_uuid = None # UUID for session
        self.readables = [self.__socket]
        self.tun_fd = None
        self.__keep_alive()
        self.keep_ask = MAX_KEEP_ASK


    def init_local_ip(self):
        '''
        获取本机ip
        '''
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.connect(('8.8.8.8', 80))
        self.local_ip = _socket.getsockname()[0]
        COLOR_LOG.info('Local IP: %s', self.local_ip)
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
        持续登录，失败后等待3秒，知道登录为止
        '''
        request = Encapsulator.make_fake_request(UUID, LOGIN_MSG, HOST_NAME)
        while True:
            self.__socket.sendto(request, DOMAIN_NS_ADDR)
            COLOR_LOG.info('Send data in DNS request')
            response, _addr = self.__socket.recvfrom(2048)
            try:
                if self.__decode_login_msg(response):
                    break
            except AssertionError:
                COLOR_LOG.info('Server Down or Not Detected Login Message')
                continue
            COLOR_LOG.info('Login Failed, Try later')
            time.sleep(3)
        COLOR_LOG.info('Connect to server successful')

    def __request_up_msg(self, data: bytes):
        '''
        请求用户上行数据 SESSION_UUID.<UNIQUE_ID>.UP.$BYTE_DATA.hostname.domain
        '''
        s_uuid = self.s_uuid+'.UP.'+ str(UUID_GENERATOR.uuid1())[:8]
        request = Encapsulator.make_fake_request(s_uuid, data, HOST_NAME)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        COLOR_LOG.info('Send data in DNS request')
        COLOR_LOG.debug(request)
        self.__keep_ask(True)

    def __request_down_msg(self):
        '''
        请求用户下行数据 SESSION_UUID.DOWN.<RANDOM_UUID>.hostname.domain
        '''
        time.sleep(0.01)
        d_uuid = self.s_uuid+'.DOWN'
        r_uuid = str(UUID_GENERATOR.uuid1())
        request = Encapsulator.make_fake_request(d_uuid, r_uuid.encode(), HOST_NAME)
        self.__socket.sendto(request, DOMAIN_NS_ADDR)
        COLOR_LOG.info('Send DOWN MSG in DNS request %s', r_uuid)
        COLOR_LOG.info(request)

    @staticmethod
    def __decode_down_msg(response):
        '''
        解析用户下行数据
        '''
        rdata = Decapsulator.get_txt_record(response)
        if len(rdata) < 1:
            COLOR_LOG.debug('No TXT record in response')
            return b''
        return rdata

    def __decode_login_msg(self, response):
        '''
        解析用户登录响应
        '''
        name_data = Decapsulator.get_host_name(response)
        if name_data[1] != LOGIN_MSG:
            COLOR_LOG.debug('Not a Login response <%s>', name_data[1])
            return False
        try:
            txt_record = Decapsulator.get_txt_record(response)
            txt_record = txt_record.decode()
        except UnicodeDecodeError:
            COLOR_LOG.error('Wrong Login response: %s', txt_record)
            time.sleep(1)
            return False
        self.tun_fd, tun_name = TunManager.create_tunnel()
        self.readables.append(self.tun_fd)
        _login_response = txt_record.split(';')
        if len(_login_response) != 3:
            COLOR_LOG.debug('Not a Login response <%s>', txt_record)
            return False
        self.s_uuid, local_ip, peer_ip = _login_response
        COLOR_LOG.info('Session UUID: %s \tLocal ip: %s\tPeer ip: %s',\
                        self.s_uuid, local_ip, peer_ip)
        TunManager.start_tunnel(tun_name, local_ip, peer_ip, MTU)
        COLOR_LOG.info('Create Tun Successfully! Tun ID = %d', self.tun_fd)
        return True

    def __handle_dns_response(self, response):
        '''
        处理UDP客户端接受的
        '''
        name_data = Decapsulator.get_host_name(response)
        if name_data[1] == LOGIN_MSG:   # b'LOGIN':
            COLOR_LOG.error('Ignore Server Response: Already Login')
            return
        if name_data[1] == DOWN_MSG:    # b'DOWN':
            COLOR_LOG.debug('Receive Packet from server %s', name_data[2][:8])
            bytes_write = self.__decode_down_msg(response)
            if bytes_write == CLOSED_SESSION_MSG:
                # 重新登录
                # - 关闭旧的session, 原地发起登录请求
                COLOR_LOG.info('客户端掉线，重新登录')
                # - 删除旧的文件描述符
                os.close(self.readables[1])
                self.readables = [self.__socket]
                raise SessionExpiredException
            if bytes_write is not None and len(bytes_write) > 20:
                # Check if IPPacket
                # COLOR_LOG.info(IPPacket.str_info(bytes_write))
                COLOR_LOG.debug('Write data into TUN')
                COLOR_LOG.info(bytes_write)
                os.write(self.tun_fd, bytes_write)
                # 收到数据包后+1
                self.__keep_ask(True)
            else:
                # 收到空包后-1
                self.__keep_ask(False)
            return
        if name_data[1] == UP_MSG:      # b'UP'
            COLOR_LOG.debug('Server Response Invalid Question')
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
                    COLOR_LOG.debug('Get outbounding data from TUN')
                    self.__request_up_msg(ip_packet)
                    # 发送心跳包，尝试接受数据
                    COLOR_LOG.debug('keep_ask = [%d]', self.keep_ask)
                    if self.keep_ask > 0:
                        COLOR_LOG.info('Try To Receive Data [%d]', self.keep_ask)
                        self.__request_down_msg()

    def run_forever(self):
        '''
        运行代理客户端
        '''
        COLOR_LOG.info('Start connect to server...')
        self.__handle_login()
        while True:
            try:
                self.__handle_forwarding()
            except SessionExpiredException:
                COLOR_LOG.error('SessionExpiredException')
                self.__handle_login()
                continue
            except KeyboardInterrupt:
                # TODO: close the connection
                raise KeyboardInterrupt

if __name__ == '__main__':
    DOMAIN_NS_ADDR = ('120.78.166.34', 53)
    # DOMAIN_NS_ADDR = ('8.8.8.8', 53)
    DOMAIN_NS_ADDR = ('18.162.114.192', 53)
    # DOMAIN_NS_ADDR = ('18.162.51.192', 53) # 29 Kbps => 140kbps
    DOMAIN_NS_ADDR = ('47.100.92.248', 53)
    try:
        Client().run_forever()
    except KeyboardInterrupt:
        COLOR_LOG.info('Closing vpn client ...')
